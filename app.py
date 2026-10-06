import asyncio
import threading
import time
import os
import json
import requests
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    return ("", 204)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CHECK_LOG_FILE = os.path.join(BASE_DIR, "check_log.txt")
TIMEOUT_LOG_FILE = os.path.join(BASE_DIR, "timeout_log.txt")

XOR_KEY = 0x9F
PROBE_CIPHER = bytes.fromhex(
    "6B DB 89 9E 55 CF 9A 9F 51 05 9D 9F D4 CA DE D6 CC D6 D9 DA D1 D8"
)

# 日志上限
MAX_CHECK_LOG = 100       # 实时检测日志
MAX_TIMEOUT_LOG = 1000    # 超时告警日志

DEFAULT_CONFIG = {
    "port": 6732,
    "interval": 20,
    "timeout": 1.5,
    "alert_streak": 5,
    "bark_keys": [],
    "maintenance_windows": [],   # 新增：["周一~周五 07:00-07:30", ...]
    "timezone_offset": 8,
    "sidebar_collapsed": False,
    "servers": [],
}

_config_lock = threading.Lock()

# 中文星期映射
WEEKDAY_CN = {
    "周一": 1, "周二": 2, "周三": 3, "周四": 4, "周五": 5,
    "周六": 6, "周日": 7, "周天": 7,
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "bark_key" in cfg and not isinstance(cfg.get("bark_keys"), list):
            old = cfg.pop("bark_key", "") or ""
            cfg["bark_keys"] = [{"key": old, "enabled": True}] if old.strip() else []
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        for s in cfg.get("servers", []):
            s.setdefault("enabled", True)
        cleaned = []
        for bk in cfg.get("bark_keys", []):
            if isinstance(bk, str):
                bk = {"key": bk, "enabled": True}
            key = (bk.get("key") or "").strip()
            if not key:
                continue
            cleaned.append({"key": key, "enabled": bool(bk.get("enabled", True))})
        cfg["bark_keys"] = cleaned
        # 清洗 maintenance_windows
        cfg["maintenance_windows"] = [
            str(w).strip() for w in cfg.get("maintenance_windows", [])
            if str(w).strip()
        ]
        return cfg
    except Exception:
        return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def now_str(offset=8):
    return datetime.now(timezone(timedelta(hours=offset))).strftime("%Y-%m-%d %H:%M:%S")


# ==================== 维护时段解析 ====================

def parse_maintenance_windows(windows):
    """解析维护时段字符串列表 -> [(d1, d2, t1_min, t2_min), ...]"""
    parsed = []
    for w in windows or []:
        w = (w or "").strip()
        if not w:
            continue
        parts = w.split()
        if len(parts) < 2:
            continue
        day_part, time_part = parts[0], parts[1]

        # 星期范围
        day_part = day_part.replace("～", "~")
        if "~" in day_part:
            d1s, d2s = day_part.split("~", 1)
            d1 = WEEKDAY_CN.get(d1s.strip(), 0)
            d2 = WEEKDAY_CN.get(d2s.strip(), 0)
        else:
            d1 = d2 = WEEKDAY_CN.get(day_part.strip(), 0)
        if d1 == 0 or d2 == 0:
            continue

        # 时间范围
        time_part = time_part.replace("～", "~")
        if "-" not in time_part:
            continue
        t1s, t2s = time_part.split("-", 1)
        try:
            h1, m1 = t1s.strip().split(":")
            h2, m2 = t2s.strip().split(":")
            t1 = int(h1) * 60 + int(m1)
            t2 = int(h2) * 60 + int(m2)
        except Exception:
            continue

        parsed.append((d1, d2, t1, t2))
    return parsed


def is_in_maintenance(parsed_windows, dt):
    """检查 dt 是否落在任意维护窗口内"""
    if not parsed_windows:
        return False
    wd = dt.isoweekday()
    hm = dt.hour * 60 + dt.minute
    for d1, d2, t1, t2 in parsed_windows:
        if d1 <= d2:
            day_ok = d1 <= wd <= d2
        else:
            day_ok = wd >= d1 or wd <= d2
        if not day_ok:
            continue
        if t1 <= t2:
            time_ok = t1 <= hm < t2
        else:
            time_ok = hm >= t1 or hm < t2
        if time_ok:
            return True
    return False


# ==================== 全局状态 ====================

STATE = {
    "running": False,
    "start_time": None,
    "last_check": None,
    "timezone_offset": 8,
    "results": {},
    "logs": [],
    "timeout_logs": [],
    "bark_suppressed": False,   # 当前是否因维护时段被抑制（供前端展示）
}
STATE_LOCK = threading.Lock()

monitor_thread = None
stop_event = threading.Event()


def restore_logs_from_file():
    if os.path.exists(CHECK_LOG_FILE):
        try:
            with open(CHECK_LOG_FILE, "r", encoding="utf-8") as f:
                lines = [l.rstrip("\n") for l in f.readlines() if l.strip()]
            with STATE_LOCK:
                STATE["logs"] = lines[-MAX_CHECK_LOG:]
            print(f"[boot] 恢复了 {len(STATE['logs'])} 条检测日志")
        except Exception as e:
            print(f"[boot] 恢复检测日志失败：{e}")
    if os.path.exists(TIMEOUT_LOG_FILE):
        try:
            with open(TIMEOUT_LOG_FILE, "r", encoding="utf-8") as f:
                lines = [l.rstrip("\n") for l in f.readlines() if l.strip()]
            with STATE_LOCK:
                STATE["timeout_logs"] = lines[-MAX_TIMEOUT_LOG:]
            print(f"[boot] 恢复了 {len(STATE['timeout_logs'])} 条超时日志")
        except Exception as e:
            print(f"[boot] 恢复超时日志失败：{e}")


def xor_decrypt(data, key=XOR_KEY):
    return bytes(b ^ key for b in data)


def append_log_to_file(path, line, max_lines=None):
    lines = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            lines = []
    lines.append(line.rstrip("\n") + "\n")
    if max_lines and len(lines) > max_lines:
        lines = lines[-max_lines:]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception:
        pass


async def check_one(name, ip, port, timeout, sem):
    async with sem:
        start = time.perf_counter()
        writer = None
        try:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
            except asyncio.TimeoutError:
                return name, ip, False, 0.0, (time.perf_counter() - start) * 1000, "TCP 超时"
            except ConnectionRefusedError:
                return name, ip, False, 0.0, (time.perf_counter() - start) * 1000, "拒绝连接"
            except Exception as e:
                return name, ip, False, 0.0, (time.perf_counter() - start) * 1000, str(e)

            rtt_ms = (time.perf_counter() - start) * 1000
            writer.write(PROBE_CIPHER)
            await writer.drain()

            try:
                resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                return name, ip, False, rtt_ms, (time.perf_counter() - start) * 1000, "无回包"

            if not resp:
                return name, ip, False, rtt_ms, (time.perf_counter() - start) * 1000, "无回包"

            dec = xor_decrypt(resp, XOR_KEY)
            total_ms = (time.perf_counter() - start) * 1000

            if len(dec) >= 4 and dec[0] == 0xF4 and dec[1] == 0x44:
                payload = dec[3:]
                if len(payload) >= 1 and payload[0] == 0x01:
                    return name, ip, True, rtt_ms, total_ms, ""
                else:
                    return name, ip, False, rtt_ms, total_ms, f"payload[0]={payload[0]:02X}"
            else:
                return name, ip, False, rtt_ms, total_ms, "回包非 F4 44"
        except Exception as e:
            return name, ip, False, 0.0, (time.perf_counter() - start) * 1000, str(e)
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


def send_bark_alert(device_key, name, ip, port, first_timeout_time, streak):
    if not device_key:
        return False
    payload = {
        "device_key": device_key,
        "title": f"⚠️ 服务器离线：{name}",
        "body": (
            f"服务器：{name}\n"
            f"IP：{ip}:{port}\n"
            f"首次超时：{first_timeout_time}\n"
            f"连续超时：{streak} 次"
        ),
        "group": "金庸群侠传监控",
        "ttl": 600,
        "level": "critical",
        "sound": "alarm",
        "volume": "10",
        "call": "1",
    }
    try:
        r = requests.post("https://api.day.app/push", json=payload, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def send_bark_alerts_to_all(bark_keys, name, ip, port, first_timeout_time, streak):
    for bk in bark_keys:
        if not bk.get("enabled", True):
            continue
        key = (bk.get("key") or "").strip()
        if not key:
            continue
        send_bark_alert(key, name, ip, port, first_timeout_time, streak)


async def monitor_loop(initial_cfg):
    sem = asyncio.Semaphore(20)
    streak_map = {}
    first_timeout_map = {}
    grace_rounds = 2
    round_count = 0

    with STATE_LOCK:
        STATE["running"] = True
        STATE["start_time"] = now_str(initial_cfg.get("timezone_offset", 8))
        STATE["timezone_offset"] = initial_cfg.get("timezone_offset", 8)

    while not stop_event.is_set():
        round_count += 1

        try:
            with _config_lock:
                cfg = load_config()
            port = int(cfg.get("port", 6732))
            interval = float(cfg.get("interval", 20))
            timeout = float(cfg.get("timeout", 1.5))
            alert_streak = int(cfg.get("alert_streak", 5))
            bark_keys = cfg.get("bark_keys", [])
            tz_offset = int(cfg.get("timezone_offset", 8))
            servers = [s for s in cfg.get("servers", []) if s.get("enabled", True)]
            parsed_windows = parse_maintenance_windows(cfg.get("maintenance_windows", []))
        except Exception as e:
            print(f"[monitor] 读配置失败：{e}")
            servers, bark_keys, parsed_windows = [], [], []
            interval, tz_offset = 20, 8

        try:
            tz = timezone(timedelta(hours=tz_offset))
            current_dt = datetime.now(tz)
            now_s = current_dt.strftime("%Y-%m-%d %H:%M:%S")

            in_maint = is_in_maintenance(parsed_windows, current_dt)
            with STATE_LOCK:
                STATE["bark_suppressed"] = in_maint

            results = []
            if servers:
                try:
                    results = await asyncio.gather(
                        *(check_one(s["name"], s["ip"], port, timeout, sem) for s in servers),
                        return_exceptions=True,
                    )
                except Exception as e:
                    print(f"[monitor] gather 异常：{e}")
                    results = []

            log_parts = [f"[{now_s}]"]
            alerts_to_send = []

            active_names = {s["name"] for s in servers}
            for k in list(streak_map.keys()):
                if k not in active_names:
                    streak_map.pop(k, None)
                    first_timeout_map.pop(k, None)
                    with STATE_LOCK:
                        STATE["results"].pop(k, None)

            for item in results:
                if isinstance(item, Exception):
                    print(f"[monitor] 单包异常：{item}")
                    continue
                name, ip, ok, rtt_ms, total_ms, err = item

                if ok:
                    log_parts.append(f"{name}=在线")
                    streak_map[name] = 0
                    first_timeout_map.pop(name, None)
                else:
                    log_parts.append(f"{name}=离线({err})")
                    streak_map[name] = streak_map.get(name, 0) + 1
                    streak = streak_map[name]
                    if name not in first_timeout_map:
                        first_timeout_map[name] = now_s

                    timeout_line = f"[{now_s}] {name} ({ip}:{port}) - {err}  [连续第 {streak} 次]"
                    # 超时日志写入文件（FIFO 淘汰）+ 内存
                    append_log_to_file(TIMEOUT_LOG_FILE, timeout_line, max_lines=MAX_TIMEOUT_LOG)
                    with STATE_LOCK:
                        STATE["timeout_logs"].append(timeout_line)
                        if len(STATE["timeout_logs"]) > MAX_TIMEOUT_LOG:
                            STATE["timeout_logs"] = STATE["timeout_logs"][-MAX_TIMEOUT_LOG:]

                    # 维护时段内不触发 Bark
                    if (round_count > grace_rounds
                            and streak >= alert_streak
                            and streak % alert_streak == 0
                            and not in_maint):
                        alerts_to_send.append((name, ip, first_timeout_map[name], streak))

                with STATE_LOCK:
                    STATE["results"][name] = {
                        "name": name,
                        "ip": ip,
                        "port": port,
                        "ok": ok,
                        "rtt_ms": round(rtt_ms, 1),
                        "total_ms": round(total_ms, 1),
                        "err": err,
                        "streak": streak_map.get(name, 0),
                        "first_timeout": first_timeout_map.get(name),
                        "last_check": now_s,
                    }

            log_line = " ".join(log_parts) if servers else f"[{now_s}] 无启用的服务器"
            append_log_to_file(CHECK_LOG_FILE, log_line, max_lines=MAX_CHECK_LOG)

            with STATE_LOCK:
                STATE["last_check"] = now_s
                STATE["logs"].append(log_line)
                if len(STATE["logs"]) > MAX_CHECK_LOG:
                    STATE["logs"] = STATE["logs"][-MAX_CHECK_LOG:]

            for name, ip, first_t, streak in alerts_to_send:
                await asyncio.to_thread(
                    send_bark_alerts_to_all, bark_keys, name, ip, port, first_t, streak
                )

        except Exception as e:
            print(f"[monitor] 本轮异常：{e}")
            import traceback
            traceback.print_exc()

        try:
            waited = 0.0
            step = 0.2
            while waited < interval and not stop_event.is_set():
                await asyncio.sleep(min(step, interval - waited))
                waited += step
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(interval)

    with STATE_LOCK:
        STATE["running"] = False


def run_monitor_in_thread(cfg):
    global monitor_thread
    stop_event.clear()

    def _run():
        try:
            asyncio.run(monitor_loop(cfg))
        except Exception as e:
            print(f"[monitor] 线程异常退出：{e}")
            import traceback
            traceback.print_exc()

    monitor_thread = threading.Thread(target=_run, daemon=True)
    monitor_thread.start()


# ==================== API ====================

@app.route("/")
def index():
    return jsonify({"name": "金庸群侠传至尊服务器监控后端", "status": "running"})


@app.route("/api/status")
def api_status():
    with STATE_LOCK:
        result = {
            "running": STATE["running"],
            "start_time": STATE["start_time"],
            "last_check": STATE["last_check"],
            "timezone_offset": STATE.get("timezone_offset", 8),
            "server_time": now_str(STATE.get("timezone_offset", 8)),
            "bark_suppressed": STATE.get("bark_suppressed", False),
            "results": list(STATE["results"].values()),
        }
    with _config_lock:
        cfg = load_config()
    result["sidebar_collapsed"] = bool(cfg.get("sidebar_collapsed", False))
    result["bark_keys"] = cfg.get("bark_keys", [])
    result["servers_config"] = cfg.get("servers", [])
    return jsonify(result)


@app.route("/api/config", methods=["GET"])
def api_get_config():
    with _config_lock:
        return jsonify(load_config())


@app.route("/api/config", methods=["POST"])
def api_set_config():
    data = request.get_json(force=True) or {}
    with _config_lock:
        cfg = load_config()
        for k in ("port", "interval", "timeout", "alert_streak",
                  "bark_keys", "servers", "timezone_offset",
                  "sidebar_collapsed", "maintenance_windows"):
            if k in data:
                cfg[k] = data[k]
        cleaned = []
        for bk in cfg.get("bark_keys", []):
            if isinstance(bk, str):
                bk = {"key": bk, "enabled": True}
            key = (bk.get("key") or "").strip()
            if not key:
                continue
            cleaned.append({"key": key, "enabled": bool(bk.get("enabled", True))})
        cfg["bark_keys"] = cleaned
        cfg["maintenance_windows"] = [
            str(w).strip() for w in cfg.get("maintenance_windows", [])
            if str(w).strip()
        ]
        for s in cfg.get("servers", []):
            s.setdefault("enabled", True)
        save_config(cfg)
    return jsonify({"ok": True, "config": cfg})


@app.route("/api/sidebar/toggle", methods=["POST"])
def api_sidebar_toggle():
    data = request.get_json(force=True) or {}
    collapsed = bool(data.get("collapsed", False))
    with _config_lock:
        cfg = load_config()
        cfg["sidebar_collapsed"] = collapsed
        save_config(cfg)
    return jsonify({"ok": True, "collapsed": collapsed})


@app.route("/api/servers/toggle", methods=["POST"])
def api_toggle_server():
    data = request.get_json(force=True) or {}
    name = data.get("name")
    enabled = bool(data.get("enabled", True))
    if not name:
        return jsonify({"ok": False, "msg": "缺少 name"})
    with _config_lock:
        cfg = load_config()
        found = False
        for s in cfg.get("servers", []):
            if s["name"] == name:
                s["enabled"] = enabled
                found = True
                break
        if not found:
            return jsonify({"ok": False, "msg": "找不到该服务器"})
        save_config(cfg)
    return jsonify({"ok": True})


@app.route("/api/servers/add", methods=["POST"])
def api_add_server():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    ip = (data.get("ip") or "").strip()
    if not name or not ip:
        return jsonify({"ok": False, "msg": "需要 name 和 ip"})
    with _config_lock:
        cfg = load_config()
        cfg.setdefault("servers", []).append({"name": name, "ip": ip, "enabled": True})
        save_config(cfg)
        return jsonify({"ok": True, "config": cfg})


@app.route("/api/servers/clear", methods=["POST"])
def api_clear_servers():
    with _config_lock:
        cfg = load_config()
        cfg["servers"] = []
        save_config(cfg)
    with STATE_LOCK:
        STATE["results"] = {}
    return jsonify({"ok": True})


@app.route("/api/start", methods=["POST"])
def api_start():
    global monitor_thread
    if monitor_thread and monitor_thread.is_alive():
        return jsonify({"ok": False, "msg": "监控已在运行"})
    with _config_lock:
        cfg = load_config()
    if not cfg.get("servers"):
        return jsonify({"ok": False, "msg": "服务器列表为空，请先配置"})
    run_monitor_in_thread(cfg)
    return jsonify({"ok": True, "msg": "监控已启动"})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    stop_event.set()
    return jsonify({"ok": True, "msg": "已发送停止信号"})


@app.route("/api/logs")
def api_logs():
    with STATE_LOCK:
        return jsonify({
            "logs": STATE["logs"][-MAX_CHECK_LOG:],
            "timeout_logs": STATE["timeout_logs"][-MAX_TIMEOUT_LOG:],
        })


@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    data = request.get_json(force=True) or {}
    which = data.get("which", "all")
    with STATE_LOCK:
        if which in ("all", "check"):
            STATE["logs"] = []
            try:
                open(CHECK_LOG_FILE, "w").close()
            except Exception:
                pass
        if which in ("all", "timeout"):
            STATE["timeout_logs"] = []
            try:
                open(TIMEOUT_LOG_FILE, "w").close()
            except Exception:
                pass
    return jsonify({"ok": True})


restore_logs_from_file()

_boot_cfg = load_config()
if _boot_cfg.get("servers"):
    run_monitor_in_thread(_boot_cfg)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)