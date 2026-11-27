#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub 免费节点采集 -> 解析 -> 去重 -> TCP -> 配置合法 -> 真实穿透 -> 稳定性复验"""
import base64, json, os, re, socket, ssl, subprocess, sys, time, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

WORK = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(WORK, "src")
XRAY = os.path.join(WORK, "xray", "xray")
TARGET_HOST = "www.gstatic.com"
TARGET_PATH = "/generate_204"

SOURCES = {
"freefq": "https://raw.githubusercontent.com/freefq/free/master/v2",
"pawdroid": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
"ripao": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
"ermaozi": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
"ermaozi01": "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
"mahdibland": "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
"mahdibland_merge": "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
"nomorewalls": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
"cg1": "https://q3dlaxpoaq.github.io/APIs/cg1.txt",
"cg2": "https://q3dlaxpoaq.github.io/APIs/cg2.txt",
"cg3": "https://q3dlaxpoaq.github.io/APIs/cg3.txt",
"aliilapro": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
"aliilapro_sub": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
"autoproxy": "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
"autoproxy1": "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
"roosterkid": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
"tssf": "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
}
SUPPORTED = ("vmess", "vless", "trojan", "ss")
NET_OK = ("tcp", "ws", "grpc", "h2", "httpupgrade", "xhttp", "splithttp", "http")


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def strip_insecure(ob):
    """Xray 26 已移除 tlsSettings.allowInsecure"""
    ss = ob.get("streamSettings") or {}
    for k in ("tlsSettings", "realitySettings"):
        if isinstance(ss.get(k), dict):
            ss[k].pop("allowInsecure", None)
            ss[k].pop("allowinsecure", None)
    ob["streamSettings"] = ss
    return ob


def stream(net, sec, q, host_default=""):
    ss = {"network": net if net in NET_OK else "tcp"}
    path = q.get("path", [""])[0] or "/"
    host = q.get("host", [""])[0] or host_default
    if ss["network"] in ("ws", "httpupgrade", "xhttp", "splithttp"):
        ss[{"ws": "wsSettings", "httpupgrade": "wsSettings", "xhttp": "xhttpSettings", "splithttp": "xhttpSettings"}[ss["network"]]] = {
            "path": path, "headers": ({"Host": host} if host else {})}
        if ss["network"] in ("xhttp", "splithttp"):
            ss["xhttpSettings"] = {"path": path, "host": host} if host else {"path": path}
    elif ss["network"] == "grpc":
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}
    elif ss["network"] == "h2":
        ss["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif ss["network"] == "tcp" and q.get("headerType", [""])[0] == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {"path": [path], "headers": {"Host": [host]}}}}
    if sec in ("tls", "reality"):
        ss["security"] = sec
        sni = q.get("sni", [""])[0] or q.get("peer", [""])[0] or host
        if sec == "tls":
            ts = {}
            if sni:
                ts["serverName"] = sni
            alpn = q.get("alpn", [""])[0]
            if alpn:
                ts["alpn"] = [a for a in alpn.split(",") if a]
            if q.get("fp", [""])[0]:
                ts["fingerprint"] = q["fp"][0]
            ss["tlsSettings"] = ts
        else:
            ss["realitySettings"] = {"serverName": sni, "fingerprint": q.get("fp", ["chrome"])[0] or "chrome",
                                     "publicKey": q.get("pbk", [""])[0], "shortId": q.get("sid", [""])[0]}
    return ss


def parse_node(line):
    line = line.strip()
    if not line or "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            j = json.loads(b64d(line[8:].split("#")[0]))
            host, port = j["add"], int(j["port"])
            net = (j.get("net") or "tcp").lower()
            tls = (j.get("tls") or "").lower()
            q = {"path": [j.get("path") or "/"], "host": [j.get("host") or ""],
                 "sni": [j.get("sni") or j.get("host") or ""], "serviceName": [j.get("path") or ""],
                 "headerType": [j.get("type") or ""]}
            user = {"id": j["id"], "alterId": int(j.get("aid") or 0), "security": j.get("scy") or "auto", "level": 0}
            ob = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                  "streamSettings": stream(net, "tls" if tls in ("tls", "reality") else "", q, q["host"][0])}
        elif scheme == "vless":
            body, _, _ = line[8:].rpartition("#")
            u = urlparse("vless://" + body)
            q = {k: v for k, v in parse_qs(u.query).items()}
            user = {"id": u.username, "encryption": "none", "flow": q.get("flow", [""])[0] or "", "level": 0}
            if not user["flow"]:
                user.pop("flow")
            ob = {"protocol": "vless", "settings": {"vnext": [{"address": u.hostname, "port": u.port, "users": [user]}]},
                  "streamSettings": stream(q.get("type", ["tcp"])[0], q.get("security", [""])[0], q)}
        elif scheme == "trojan":
            body, _, _ = line[9:].rpartition("#")
            u = urlparse("trojan://" + body)
            q = {k: v for k, v in parse_qs(u.query).items()}
            ob = {"protocol": "trojan", "settings": {"servers": [{"address": u.hostname, "port": u.port,
                                                                  "password": unquote(u.username or ""), "level": 0}]},
                  "streamSettings": stream(q.get("type", ["tcp"])[0], q.get("security", ["tls"])[0] or "tls", q)}
        elif scheme == "ss":
            body, _, _ = line[5:].rpartition("#")
            body = body.split("?")[0]
            if "@" in body:
                head, _, tail = body.rpartition("@")
                if ":" not in head:  # base64user@host:port 或 host:port
                    head = b64d(head)
                method, _, pwd = head.partition(":")
                host, _, port = tail.partition(":")
            else:
                dec = b64d(body)
                cred, _, hostport = dec.rpartition("@")
                method, _, pwd = cred.partition(":")
                host, _, port = hostport.partition(":")
            ob = {"protocol": "shadowsocks",
                  "settings": {"servers": [{"address": host, "port": int(port), "method": method, "password": pwd}]},
                  "streamSettings": {"network": "tcp"}}
        else:
            return None
        host, port = target_of(ob)
        if not host or not isinstance(port, int) or not (0 < port < 65536):
            return None
        return strip_insecure(ob)
    except Exception:
        return None


def fingerprint(ob):
    p = ob["protocol"]
    ss = ob.get("streamSettings", {})
    core = {"tcp": ss.get("tcpSettings"), "ws": ss.get("wsSettings"), "grpc": ss.get("grpcSettings"),
            "h2": ss.get("httpSettings"), "httpupgrade": ss.get("wsSettings"), "xhttp": ss.get("xhttpSettings")}.get(
        ss.get("network", "tcp"))
    if p in ("vmess", "vless"):
        v = ob["settings"]["vnext"][0]
        u = v["users"][0]
        return json.dumps([p, v["address"].lower(), v["port"], u.get("id"), u.get("flow", ""),
                           ss.get("security", ""), (ss.get("tlsSettings") or {}).get("serverName", ""),
                           (ss.get("realitySettings") or {}).get("publicKey", ""), core], sort_keys=True)
    if p == "trojan":
        s = ob["settings"]["servers"][0]
        return json.dumps([p, s["address"].lower(), s["port"], s["password"], ss.get("security", ""), core], sort_keys=True)
    s = ob["settings"]["servers"][0]
    return json.dumps([p, s["address"].lower(), s["port"], s["method"], s["password"]], sort_keys=True)


def target_of(ob):
    if ob["protocol"] in ("vmess", "vless"):
        v = ob["settings"]["vnext"][0]
        return v["address"], v["port"]
    s = ob["settings"]["servers"][0]
    return s["address"], s["port"]


# ---------- stage 1: fetch ----------
def stage_fetch():
    os.makedirs(SRC, exist_ok=True)
    for f in os.listdir(SRC):
        os.remove(os.path.join(SRC, f))
    for name, url in SOURCES.items():
        out = os.path.join(SRC, name + ".txt")
        r = subprocess.run(["curl", "-sL", "--max-time", "45", "--retry", "2",
                            "-A", "v2rayN/6.31", "-o", out, url], capture_output=True)
        size = os.path.getsize(out) if os.path.exists(out) else 0
        print("%-16s %s %d" % (name, "OK " if size > 0 else "FAIL", size), flush=True)


# ---------- stage 2: parse + dedupe ----------
def stage_parse():
    raw, ok, bad = 0, 0, 0
    seen, nodes = set(), []
    per_src = {}
    for name in sorted(os.listdir(SRC)):
        if not name.endswith(".txt"):
            continue
        txt = open(os.path.join(SRC, name), encoding="utf-8", errors="ignore").read()
        if "://" not in txt:
            try:
                txt = b64d(txt)
            except Exception:
                pass
        cnt = 0
        for line in txt.replace("\r", "").split("\n"):
            line = line.strip()
            if not line:
                continue
            raw += 1
            ob = parse_node(line)
            if not ob:
                bad += 1
                continue
            ok += 1
            fp = fingerprint(ob)
            if fp in seen:
                continue
            seen.add(fp)
            nodes.append({"proto": ob["protocol"], "outbound": ob, "target": target_of(ob), "src": name})
            cnt += 1
        per_src[name] = cnt
    json.dump(nodes, open(os.path.join(WORK, "nodes.json"), "w"), ensure_ascii=False)
    print("原始行: %d  解析成功: %d  失败/不支持: %d  去重后: %d" % (raw, ok, bad, len(nodes)))
    proto = {}
    for n in nodes:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    print("协议分布:", proto)
    print("去重后可用数（按源）:", per_src)


# ---------- stage 3: tcp ----------
def tcp_one(item):
    host, port = item["target"]
    try:
        socket.setdefaulttimeout(2.6)
        s = socket.create_connection((host, int(port)), timeout=2.6)
        s.close()
        return True
    except Exception:
        return False


def stage_tcp():
    nodes = json.load(open(os.path.join(WORK, "nodes.json")))
    alive = []
    with ThreadPoolExecutor(max_workers=300) as ex:
        futs = {ex.submit(tcp_one, n): n for n in nodes}
        done = 0
        for f in as_completed(futs):
            done += 1
            if f.result():
                alive.append(futs[f])
            if done % 500 == 0:
                print("  已测 %d/%d, 存活 %d" % (done, len(nodes), len(alive)), flush=True)
    json.dump(alive, open(os.path.join(WORK, "tcp_alive.json"), "w"), ensure_ascii=False)
    proto = {}
    for n in alive:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    print("TCP 可连通: %d / %d  协议 %s" % (len(alive), len(nodes), proto))


# ---------- precheck / batch ----------
def free_port(start):
    for p in range(start, start + 400):
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except Exception:
            continue
    raise RuntimeError("no free port")


def precheck_one(n, port):
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}}],
           "outbounds": [n["outbound"]]}
    p = os.path.join(WORK, "chk_%d.json" % port)
    json.dump(cfg, open(p, "w"))
    proc = subprocess.Popen([XRAY, "run", "-c", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.55)
    alive = proc.poll() is None
    proc.kill()
    proc.wait()
    os.remove(p)
    return alive


def stage_precheck():
    nodes = json.load(open(os.path.join(WORK, "tcp_alive.json")))
    good = []
    def work(pair):
        idx, n = pair
        return n, precheck_one(n, 10000 + (idx % 300) * 10 + 1)
    with ThreadPoolExecutor(max_workers=12) as ex:
        for i, (n, ok) in enumerate(ex.map(work, enumerate(nodes)), 1):
            if ok:
                good.append(n)
            if i % 300 == 0:
                print("  预检 %d/%d 合法 %d" % (i, len(nodes), len(good)), flush=True)
    json.dump(good, open(os.path.join(WORK, "cfg_ok.json"), "w"), ensure_ascii=False)
    print("配置合法: %d / %d" % (len(good), len(nodes)))


def socks_via(port, host=TARGET_HOST, timeout=6.0):
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            s.close(); return None
        req = b"\x05\x01\x00\x03" + len(host).to_bytes(1, "big") + host.encode() + b"\x01\xbb"
        s.sendall(req)
        rep = s.recv(2)
        if len(rep) < 2 or rep[1] != 0:
            s.close(); return None
        s.recv(rep[0] and 10)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ts = ctx.wrap_socket(s, server_hostname=host, suppress_ragged_eofs=True)
        ts.settimeout(timeout)
        ts.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: v2rayN/6.31\r\nConnection: close\r\n\r\n"
                    % (TARGET_PATH, host)).encode())
        data = ts.recv(64)
        ts.close()
        if data.startswith(b"HTTP/1.1 204") or data.startswith(b"HTTP/1.1 200") or \
           data.startswith(b"HTTP/1.0 204") or data.startswith(b"HTTP/1.0 200"):
            return int((time.time() - t0) * 1000)
        return None
    except Exception:
        return None


def run_batch(batch, base_port, timeout=6.0, workers=50):
    inbounds, rules = [], []
    for i, n in enumerate(batch):
        tag = "i%d" % i
        inbounds.append({"tag": tag, "listen": "127.0.0.1", "port": base_port + i, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}})
        rules.append({"type": "field", "inboundTag": [tag], "outboundTag": "o%d" % i})
    outbounds = [{"tag": "o%d" % i, "protocol": n["outbound"]["protocol"], "settings": n["outbound"]["settings"],
                  "streamSettings": n["outbound"]["streamSettings"]} for i, n in enumerate(batch)]
    cfg = {"log": {"loglevel": "none"}, "inbounds": inbounds,
           "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
           "routing": {"rules": rules}}
    p = os.path.join(WORK, "batch_%d.json" % base_port)
    json.dump(cfg, open(p, "w"))
    proc = subprocess.Popen([XRAY, "run", "-c", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    if proc.poll() is not None:
        os.remove(p)
        return [None] * len(batch)
    res = [None] * len(batch)
    def work(i):
        res[i] = socks_via(base_port + i, timeout=timeout)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, range(len(batch))))
    proc.kill(); proc.wait()
    os.remove(p)
    return res


def probe_all(nodes, base=41000, timeout=6.0, label=""):
    passed = []
    i = 0
    while i < len(nodes):
        batch = nodes[i:i + 100]
        if base + len(batch) > 64000:
            base = 41000
        res = run_batch(batch, base, timeout=timeout)
        for n, ms in zip(batch, res):
            if ms:
                n["proxy_ms"] = ms
                passed.append(n)
        print("  %s %d-%d: 通过 %d/%d, 累计 %d" % (label, i, i + len(batch) - 1,
                                                sum(1 for r in res if r), len(batch), len(passed)), flush=True)
        i += 100
        base += 110
    return passed


def stage_probe():
    nodes = json.load(open(os.path.join(WORK, "cfg_ok.json")))
    print("阶段2 真实穿透测试: %d 个候选" % len(nodes))
    passed = probe_all(nodes, 41000, 6.0, "批次")
    json.dump(passed, open(os.path.join(WORK, "verified.json"), "w"), ensure_ascii=False)
    proto = {}
    for n in passed:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    print("真实可用: %d  协议 %s" % (len(passed), proto))
    rest = [n for n in nodes if n not in passed]
    json.dump(rest, open(os.path.join(WORK, "rest1.json"), "w"), ensure_ascii=False)


def stage_retest():
    rest = json.load(open(os.path.join(WORK, "rest1.json")))
    passed = json.load(open(os.path.join(WORK, "verified.json")))
    print("复测待测: %d" % len(rest))
    extra = probe_all(rest, 48000, 12.0, "复测")
    passed += extra
    json.dump(passed, open(os.path.join(WORK, "verified.json"), "w"), ensure_ascii=False)
    print("复测新增: %d 合计: %d" % (len(extra), len(passed)))


def stage_confirm():
    nodes = json.load(open(os.path.join(WORK, "verified.json")))
    rounds = {}
    for r in range(3):
        res = run_batch(nodes, 52000, timeout=8.0, workers=40) if len(nodes) <= 100 else None
        if res is None:
            passed = probe_all(nodes, 52000, 8.0, "第%d轮" % (r + 1))
            keys = {json.dumps(n["outbound"], sort_keys=True) for n in passed}
        else:
            keys = {json.dumps(n["outbound"], sort_keys=True) for n, ms in zip(nodes, res) if ms}
            print("第%d轮: %d/%d 通过" % (r + 1, len(keys), len(nodes)), flush=True)
        rounds[r] = keys
    stable = []
    for n in nodes:
        k = json.dumps(n["outbound"], sort_keys=True)
        if sum(1 for r in rounds if k in rounds[r]) >= 2:
            stable.append(n)
    json.dump(stable, open(os.path.join(WORK, "stable.json"), "w"), ensure_ascii=False)
    proto = {}
    for n in stable:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    print("稳定可用（≥2/3 轮）: %d / %d 协议 %s" % (len(stable), len(nodes), proto))


if __name__ == "__main__":
    {"fetch": stage_fetch, "parse": stage_parse, "tcp": stage_tcp, "precheck": stage_precheck,
     "probe": stage_probe, "retest": stage_retest, "confirm": stage_confirm}[sys.argv[1]]()
