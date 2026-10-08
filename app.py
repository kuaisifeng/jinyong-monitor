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

MAX_CHECK_LOG = 100
MAX_TIMEOUT_LOG = 1000
DEFAULT_PORT = 6732

# ==================== Render 资源监控配置 ====================
RENDER_API_TOKEN = os.getenv("RENDER_API_TOKEN", "")
RENDER_SERVICE_ID = os.getenv("RENDER_SERVICE_ID", "")
RENDER_LIMIT_BW_MB = 5120
RENDER_LIMIT_MEM_MB = 512
RENDER_CACHE_SECONDS = 600

_render_cache = {"data": None, "expire": 0}
_render_lock = threading.Lock()

# ==================== Ntfy 推送配置 ====================
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "jinyong-server-alert")
NTFY_SERVER = "https://ntfy.sh"

# 中文星期映射
WEEKDAY_CN = {
    "周一": 1, "周二": 2, "周三": 3, "周四": 4, "周五": 5,
    "周六": 6, "周日": 7, "周天": 7, "星期一": 1, "星期二": 2,
    "星期三": 3, "星期四": 4, "星期五": 5, "星期六": 6, "星期日": 7,
}

DEFAULT_MAINTENANCE = [
    {"days": [1, 2, 3, 4, 5], "start": "07:00", "end": "07:30"},
    {"days": [6, 7], "start": "09:30", "end": "10:00"},
]

DEFAULT_CONFIG = {
    "interval": 20,
    "timeout": 1.5,
    "alert_streak": 5,
    "bark_keys": [],
    "maintenance_windows": DEFAULT_MAINTENANCE,
    "timezone_offset": 8,
    "sidebar_collapsed": False,
    "servers": [],
}

_config_lock = threading.Lock()


def parse_old_maintenance_string(s):
    parts = s.strip().split()
    if len(parts) < 2:
        return None
    day_part, time_part = parts[0], parts[1]
    day_part = day_part.replace("～", "~").replace("-", "~")
    if "~" in day_part:
        d1s, d2s = day_part.split("~", 1)
        d1 = WEEKDAY_CN.get(d1s.strip(), 0)
        d2 = WEEKDAY_CN.get(d2s.strip(), 0)
    else:
        d1 = d2 = WEEKDAY_CN.get(day_part.strip(), 0)
    if d1 == 0 or d2 == 0:
        return None
    if d1 <= d2:
        days = list(range(d1, d2 + 1))
    else:
        days = list(range(d1, 8)) + list(range(1, d2 + 1))
    time_part = time_part.replace("～", "~")
    if "-" not in time_part:
        return None
    t1s, t2s = time_part.split("-", 1)
    try:
        h1, m1 = t1s.strip().split(":")
        h2, m2 = t2s.strip().split(":")
        start = f"{int(h1):02d}:{int(m1):02d}"
        end = f"{int(h2):02d}:{int(m2):02d}"
    except Exception:
        return None
    return days, start, end


def migrate_maintenance_windows(windows):
    if windows is None:
        return [dict(w) for w in DEFAULT_MAINTENANCE]
    result = []
    for w in windows:
        if isinstance(w, dict):
            try:
                days = sorted(set(int(d) for d in (w.get("days") or []) if 1 <= int(d) <= 7))
            except Exception:
                days = []
            start = str(w.get("start") or "").strip()
            end = str(w.get("end") or "").strip()
            if days and start and end:
                result.append({"days": days, "start": start, "end": end})
        elif isinstance(w, str):
            parsed = parse_old_maintenance_string(w)
            if parsed:
                days, start, end = parsed
                result.append({"days": days, "start": start, "end": end})
    return result


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
            if k == "maintenance_windows":
                continue
            cfg.setdefault(k, v)
        for s in cfg.get("servers", []):
            s.setdefault("enabled", True)
            try:
                s["port"] = int(s.get("port") or DEFAULT_PORT)
            except Exception:
                s["port"] = DEFAULT_PORT
        cleaned = []
        for bk in cfg.get("bark_keys", []):
            if isinstance(bk, str):
                bk = {"key": bk, "enabled": True}
            key = (bk.get("key") or "").strip()
            if not key:
                continue
            cleaned.append({"key": key, "enabled": bool(bk.get("enabled", True))})
        cfg["bark_keys"] = cleaned
        cfg["maintenance_windows"] = migrate_maintenance_windows(
            cfg.get("maintenance_windows", None)
            if "maintenance_windows" in cfg else None
        )
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


def is_in_maintenance(windows, dt):
    if not windows:
        return False
    wd = dt.isoweekday()
    hm = dt.hour * 60 + dt.minute
    for w in windows:
        days = w.get("days") or []
        if wd not in days:
            continue
        try:
            h1, m1 = str(w.get("start", "")).split(":")
            h2, m2 = str(w.get("end", "")).split(":")
            t1 = int(h1) * 60 + int(m1)
            t2 = int(h2) * 60 + int(m2)
        except Exception:
            continue
        if t1 <= t2:
            if t1 <= hm < t2:
                return True
        else:
            if hm >= t1 or hm < t2:
                return True
    return False


# ==================== Render 资源监控 ====================

def fetch_render_metrics():
    if not RENDER_API_TOKEN:
        raise Exception("未配置环境变量 RENDER_API_TOKEN")
    if not RENDER_SERVICE_ID:
        raise Exception("未配置环境变量 RENDER_SERVICE_ID")

    headers = {
        "Authorization": f"Bearer {RENDER_API_TOKEN}",
        "Accept": "application/json",
    }

    now_utc = datetime.now(timezone.utc)
    start = datetime(now_utc.year, now_utc.month, 1, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    bw_url = (
        f"https://api.render.com/v1/metrics/bandwidth"
        f"?resource={RENDER_SERVICE_ID}"
        f"&startTime={start}&endTime={end}&resolutionSeconds=3600"
    )
    bw_resp = requests.get(bw_url, headers=headers, timeout=15)
    if bw_resp.status_code != 200:
        raise Exception(f"带宽 API 返回 {bw_resp.status_code}: {bw_resp.text[:200]}")
    bw_data = bw_resp.json()
    total_bw_mb = 0.0
    if isinstance(bw_data, list):
        for series in bw_data:
            for pt in series.get("values", []):
                try:
                    total_bw_mb += float(pt.get("value", 0))
                except Exception:
                    pass

    mem_url = (
        f"https://api.render.com/v1/metrics/memory"
        f"?resource={RENDER_SERVICE_ID}"
        f"&startTime={start}&endTime={end}&resolutionSeconds=3600"
    )
    mem_resp = requests.get(mem_url, headers=headers, timeout=15)
    if mem_resp.status_code != 200:
        raise Exception(f"内存 API 返回 {mem_resp.status_code}: {mem_resp.text[:200]}")
    mem_data = mem_resp.json()
    latest_ts = ""
    latest_bytes = 0.0
    if isinstance(mem_data, list):
        for series in mem_data:
            for pt in series.get("values", []):
                ts = pt.get("timestamp", "")
                if ts > latest_ts:
                    latest_ts = ts
                    try:
                        latest_bytes = float(pt.get("value", 0))
                    except Exception:
                        latest_bytes = 0.0
    mem_mb = latest_bytes / 1024 / 1024

    bw_pct = round(min(total_bw_mb / RENDER_LIMIT_BW_MB * 100, 100), 2) if RENDER_LIMIT_BW_MB else 0
    mem_pct = round(min(mem_mb / RENDER_LIMIT_MEM_MB * 100, 100), 2) if RENDER_LIMIT_MEM_MB else 0

    return {
        "bandwidth": {
            "used_mb": round(total_bw_mb, 2),
            "limit_mb": RENDER_LIMIT_BW_MB,
            "percent": bw_pct,
        },
        "memory": {
            "used_mb": round(mem_mb, 2),
            "limit_mb": RENDER_LIMIT_MEM_MB,
            "percent": mem_pct,
        },
        "memory_sample_time": latest_ts,
        "updated_at": now_str(8),
    }


STATE = {
    "running": False,
    "start_time": None,
    "last_check": None,
    "timezone_offset": 8,
    "results": {},
    "logs": [],
    "timeout_logs": [],
    "bark_suppressed": False,
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
        except Exception as e:
            print(f"[boot] 恢复检测日志失败：{e}")
    if os.path.exists(TIMEOUT_LOG_FILE):
        try:
            with open(TIMEOUT_LOG_FILE, "r", encoding="utf-8") as f:
                lines = [l.rstrip("\n") for l in f.readlines() if l.strip()]
            with STATE_LOCK:
                STATE["timeout_logs"] = lines[-MAX_TIMEOUT_LOG:]
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
            # ---- 建连阶段 ----
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
            except asyncio.TimeoutError:
                return name, ip, port, False, 0.0, (time.perf_counter() - start) * 1000, "TCP 超时"
            except ConnectionRefusedError:
                return name, ip, port, False, 0.0, (time.perf_counter() - start) * 1000, "拒绝连接"
            except ConnectionResetError:
                return name, ip, port, False, 0.0, (time.perf_counter() - start) * 1000, "连接被强制断开"
            except Exception as e:
                return name, ip, port, False, 0.0, (time.perf_counter() - start) * 1000, str(e)

            rtt_ms = (time.perf_counter() - start) * 1000

            # ---- 发包 + 收包阶段 ----
            try:
                writer.write(PROBE_CIPHER)
                await writer.drain()

                try:
                    resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                except asyncio.TimeoutError:
                    return name, ip, port, False, rtt_ms, (time.perf_counter() - start) * 1000, "无回包"
                except ConnectionResetError:
                    return name, ip, port, False, rtt_ms, (time.perf_counter() - start) * 1000, "连接被强制断开"

                if not resp:
                    return name, ip, port, False, rtt_ms, (time.perf_counter() - start) * 1000, "无回包"

                dec = xor_decrypt(resp, XOR_KEY)
                total_ms = (time.perf_counter() - start) * 1000

                if len(dec) >= 4 and dec[0] == 0xF4 and dec[1] == 0x44:
                    payload = dec[3:]
                    if len(payload) >= 1 and payload[0] == 0x01:
                        return name, ip, port, True, rtt_ms, total_ms, ""
                    else:
                        return name, ip, port, False, rtt_ms, total_ms, f"payload[0]={payload[0]:02X}"
                else:
                    return name, ip, port, False, rtt_ms, total_ms, "回包非 F4 44"
            except ConnectionResetError:
                return name, ip, port, False, rtt_ms, (time.perf_counter() - start) * 1000, "连接被强制断开"
            except Exception as e:
                return name, ip, port, False, rtt_ms, (time.perf_counter() - start) * 1000, str(e)
        except Exception as e:
            return name, ip, port, False, 0.0, (time.perf_counter() - start) * 1000, str(e)
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


def send_ntfy_alert(name, ip, port, first_timeout_time, streak):
    """向 Ntfy 频道发送报警（JSON API + 详细日志）"""
    if not NTFY_TOPIC:
        print("[Ntfy] 未配置 NTFY_TOPIC，跳过", flush=True)
        return False
    payload = {
        "topic": NTFY_TOPIC,
        "title": f"⚠️ 服务器离线：{name}",
        "message": (
            f"服务器：{name}\n"
            f"IP：{ip}:{port}\n"
            f"首次超时：{first_timeout_time}\n"
            f"连续超时：{streak} 次"
        ),
        "priority": 5,
        "tags": ["warning", "skull"],
    }
    try:
        r = requests.post(
            NTFY_SERVER,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "jinyong-monitor/1.0",
            },
            timeout=10,
        )
        print(
            f"[Ntfy] HTTP {r.status_code} | topic={NTFY_TOPIC} | resp={r.text[:200]}",
            flush=True,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"[Ntfy] 发送异常: {type(e).__name__}: {e}", flush=True)
        return False


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
            interval = float(cfg.get("interval", 20))
            timeout = float(cfg.get("timeout", 1.5))
            alert_streak = int(cfg.get("alert_streak", 5))
            bark_keys = cfg.get("bark_keys", [])
            tz_offset = int(cfg.get("timezone_offset", 8))
            servers = [s for s in cfg.get("servers", []) if s.get("enabled", True)]
            maintenance_windows = cfg.get("maintenance_windows", [])
        except Exception as e:
            print(f"[monitor] 读配置失败：{e}")
            servers, bark_keys, maintenance_windows = [], [], []
            interval, tz_offset = 20, 8

        try:
            tz = timezone(timedelta(hours=tz_offset))
            current_dt = datetime.now(tz)
            now_s = current_dt.strftime("%Y-%m-%d %H:%M:%S")

            in_maint = is_in_maintenance(maintenance_windows, current_dt)
            with STATE_LOCK:
                STATE["bark_suppressed"] = in_maint

            results = []
            if servers:
                try:
                    results = await asyncio.gather(
                        *(check_one(s["name"], s["ip"], int(s.get("port", DEFAULT_PORT)),
                                    timeout, sem) for s in servers),
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
                name, ip, port, ok, rtt_ms, total_ms, err = item

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
                    append_log_to_file(TIMEOUT_LOG_FILE, timeout_line, max_lines=MAX_TIMEOUT_LOG)
                    with STATE_LOCK:
                        STATE["timeout_logs"].append(timeout_line)
                        if len(STATE["timeout_logs"]) > MAX_TIMEOUT_LOG:
                            STATE["timeout_logs"] = STATE["timeout_logs"][-MAX_TIMEOUT_LOG:]

                    if (round_count > grace_rounds
                            and streak >= alert_streak
                            and streak % alert_streak == 0
                            and not in_maint):
                        alerts_to_send.append((name, ip, port, first_timeout_map[name], streak))

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

            for name, ip, port, first_t, streak in alerts_to_send:
                await asyncio.to_thread(
                    send_bark_alerts_to_all, bark_keys, name, ip, port, first_t, streak
                )
                await asyncio.to_thread(
                    send_ntfy_alert, name, ip, port, first_t, streak
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
    result["ntfy_topic"] = NTFY_TOPIC
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
        for k in ("interval", "timeout", "alert_streak",
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
        servers_clean = []
        for s in cfg.get("servers", []):
            name = (s.get("name") or "").strip()
            ip = (s.get("ip") or "").strip()
            if not name or not ip:
                continue
            try:
                port = int(s.get("port") or DEFAULT_PORT)
            except Exception:
                port = DEFAULT_PORT
            servers_clean.append({
                "name": name,
                "ip": ip,
                "port": port,
                "enabled": bool(s.get("enabled", True)),
            })
        cfg["servers"] = servers_clean
        cfg["maintenance_windows"] = migrate_maintenance_windows(cfg.get("maintenance_windows"))
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


@app.route("/api/render_resource")
def api_render_resource():
    now_ts = time.time()
    with _render_lock:
        if _render_cache["data"] is not None and now_ts < _render_cache["expire"]:
            return jsonify(_render_cache["data"])
    try:
        data = fetch_render_metrics()
        with _render_lock:
            _render_cache["data"] = data
            _render_cache["expire"] = now_ts + RENDER_CACHE_SECONDS
        return jsonify(data)
    except Exception as e:
        with _render_lock:
            if _render_cache["data"] is not None:
                return jsonify(_render_cache["data"])
        return jsonify({"error": str(e)}), 500


restore_logs_from_file()

_boot_cfg = load_config()
if _boot_cfg.get("servers"):
    run_monitor_in_thread(_boot_cfg)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)