# app.py - 金庸群侠传至尊服务器监控后端
import asyncio
import threading
import time
import os
import json
import requests
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)


# ==================== 跨域支持（Cloudflare Pages 要访问这里） ====================
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    return ("", 204)


# ==================== 基础配置 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CHECK_LOG_FILE = os.path.join(BASE_DIR, "check_log.txt")
TIMEOUT_LOG_FILE = os.path.join(BASE_DIR, "timeout_log.txt")

XOR_KEY = 0x9F
PROBE_CIPHER = bytes.fromhex(
    "6B DB 89 9E 55 CF 9A 9F 51 05 9D 9F D4 CA DE D6 CC D6 D9 DA D1 D8"
)

MAX_LOG_ENTRIES = 100

# 默认配置（首次启动时写入 config.json）
DEFAULT_CONFIG = {
    "port": 6732,
    "interval": 20,        # 检测间隔（秒）
    "timeout": 1.5,        # 单次连接/收包超时（秒）
    "alert_streak": 5,     # 连续超时多少次触发 Bark 报警
    "bark_key": "",        # Bark device_key
    "servers": [],         # [{"name": "18区", "ip": "49.234.85.110"}, ...]
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ==================== 全局运行状态 ====================
STATE = {
    "running": False,
    "start_time": None,
    "last_check": None,
    "results": {},        # name -> 结果字典
    "logs": [],           # 最近 100 条检测日志
    "timeout_logs": [],   # 超时日志
}
STATE_LOCK = threading.Lock()

monitor_thread = None
stop_event = threading.Event()


# ==================== 工具函数 ====================
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


# ==================== 探针检测 ====================
async def check_one(name, ip, port, timeout, sem):
    async with sem:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            total_ms = (time.perf_counter() - start) * 1000
            return name, ip, False, 0.0, total_ms, "TCP 超时"
        except ConnectionRefusedError:
            total_ms = (time.perf_counter() - start) * 1000
            return name, ip, False, 0.0, total_ms, "拒绝连接"
        except Exception as e:
            total_ms = (time.perf_counter() - start) * 1000
            return name, ip, False, 0.0, total_ms, str(e)

        rtt_ms = (time.perf_counter() - start) * 1000

        try:
            writer.write(PROBE_CIPHER)
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                total_ms = (time.perf_counter() - start) * 1000
                return name, ip, False, rtt_ms, total_ms, "无回包"
            if not resp:
                total_ms = (time.perf_counter() - start) * 1000
                return name, ip, False, rtt_ms, total_ms, "无回包"
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
            total_ms = (time.perf_counter() - start) * 1000
            return name, ip, False, rtt_ms, total_ms, str(e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ==================== Bark 报警 ====================
def send_bark_alert(bark_key, name, ip, port, first_timeout_time, streak):
    if not bark_key:
        return False
    payload = {
        "device_key": bark_key,
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


# ==================== 监控主循环 ====================
async def monitor_loop(cfg):
    port = cfg["port"]
    interval = cfg["interval"]
    timeout = cfg["timeout"]
    alert_streak = cfg["alert_streak"]
    bark_key = cfg["bark_key"]
    servers = cfg["servers"]

    sem = asyncio.Semaphore(20)
    streak_map = {}
    first_timeout_map = {}
    grace_rounds = 2   # 启动宽限：前 2 轮即使超时也不报警
    round_count = 0

    with STATE_LOCK:
        STATE["running"] = True
        STATE["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    while not stop_event.is_set():
        round_count += 1
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        results = await asyncio.gather(
            *(check_one(s["name"], s["ip"], port, timeout, sem) for s in servers)
        )

        log_parts = [f"[{now_str}]"]
        alerts_to_send = []
        new_results = {}

        for name, ip, ok, rtt_ms, total_ms, err in results:
            if ok:
                log_parts.append(f"{name}=在线")
                streak_map[name] = 0
                first_timeout_map.pop(name, None)
            else:
                log_parts.append(f"{name}=离线({err})")
                streak_map[name] = streak_map.get(name, 0) + 1
                streak = streak_map[name]
                if name not in first_timeout_map:
                    first_timeout_map[name] = now_str

                timeout_line = f"[{now_str}] {name} ({ip}:{port}) - {err}  [连续第 {streak} 次]"
                append_log_to_file(TIMEOUT_LOG_FILE, timeout_line)
                with STATE_LOCK:
                    STATE["timeout_logs"].append(timeout_line)
                    if len(STATE["timeout_logs"]) > 500:
                        STATE["timeout_logs"] = STATE["timeout_logs"][-500:]

                if (round_count > grace_rounds
                        and streak >= alert_streak
                        and streak % alert_streak == 0):
                    alerts_to_send.append((name, ip, first_timeout_map[name], streak))

            new_results[name] = {
                "name": name,
                "ip": ip,
                "port": port,
                "ok": ok,
                "rtt_ms": round(rtt_ms, 1),
                "total_ms": round(total_ms, 1),
                "err": err,
                "streak": streak_map.get(name, 0),
                "first_timeout": first_timeout_map.get(name),
                "last_check": now_str,
            }

        log_line = " ".join(log_parts)
        append_log_to_file(CHECK_LOG_FILE, log_line, max_lines=MAX_LOG_ENTRIES)

        with STATE_LOCK:
            STATE["last_check"] = now_str
            STATE["results"] = new_results
            STATE["logs"].append(log_line)
            if len(STATE["logs"]) > MAX_LOG_ENTRIES:
                STATE["logs"] = STATE["logs"][-MAX_LOG_ENTRIES:]

        for name, ip, first_t, streak in alerts_to_send:
            await asyncio.to_thread(send_bark_alert, bark_key, name, ip, port, first_t, streak)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass

    with STATE_LOCK:
        STATE["running"] = False


def run_monitor_in_thread(cfg):
    global monitor_thread
    stop_event.clear()

    def _run():
        asyncio.run(monitor_loop(cfg))

    monitor_thread = threading.Thread(target=_run, daemon=True)
    monitor_thread.start()


# ==================== API 接口 ====================
@app.route("/")
def index():
    return jsonify({
        "name": "金庸群侠传至尊服务器监控后端",
        "status": "running",
    })


@app.route("/api/status")
def api_status():
    with STATE_LOCK:
        return jsonify({
            "running": STATE["running"],
            "start_time": STATE["start_time"],
            "last_check": STATE["last_check"],
            "results": list(STATE["results"].values()),
        })


@app.route("/api/config", methods=["GET"])
def api_get_config():
    return jsonify(load_config())


@app.route("/api/config", methods=["POST"])
def api_set_config():
    data = request.get_json(force=True) or {}
    cfg = load_config()
    for k in ("port", "interval", "timeout", "alert_streak", "bark_key", "servers"):
        if k in data:
            cfg[k] = data[k]
    save_config(cfg)
    return jsonify({"ok": True, "config": cfg})


@app.route("/api/start", methods=["POST"])
def api_start():
    global monitor_thread
    if monitor_thread and monitor_thread.is_alive():
        return jsonify({"ok": False, "msg": "监控已在运行"})
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
            "logs": STATE["logs"][-MAX_LOG_ENTRIES:],
            "timeout_logs": STATE["timeout_logs"][-500:],
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


# ==================== 模块加载时自动启动监控（gunicorn 也能触发） ====================
_boot_cfg = load_config()
if _boot_cfg.get("servers"):
    run_monitor_in_thread(_boot_cfg)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)