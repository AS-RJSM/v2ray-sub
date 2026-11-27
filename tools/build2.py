#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重建分享链接（云主机版，含一致性校验与 tcp+http 回写修复）"""
import base64, json, os, sys, time, urllib.parse

WORK = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "/home/user/Doubao/chats/38452101219217922"


def b64(s):
    return base64.b64encode(s.encode()).decode()


def _tcp_http(ss):
    t = (ss.get("tcpSettings") or {}).get("header", {})
    return t.get("type") == "http", t.get("request", {}) or {}


def rebuild(n, idx):
    ob = n["outbound"]
    p = ob["protocol"]
    ss = ob.get("streamSettings", {})
    net = ss.get("network", "tcp")
    sec = ss.get("security", "")
    remark = "V2R-%03d·%s·%dms" % (idx, p[:4].upper(), n.get("proxy_ms", 0))

    if p == "vmess":
        v = ob["settings"]["vnext"][0]
        u = v["users"][0]
        j = {"v": "2", "ps": remark, "add": v["address"], "port": str(v["port"]),
             "id": u["id"], "aid": str(u.get("alterId", 0)), "scy": u.get("security", "auto"),
             "net": net, "type": "none", "host": "", "path": "", "tls": "", "sni": ""}
        if net in ("ws", "httpupgrade"):
            j["path"] = ss.get("wsSettings", {}).get("path", "/")
            j["host"] = ss.get("wsSettings", {}).get("headers", {}).get("Host", "")
        elif net in ("xhttp", "splithttp"):
            j["net"] = "xhttp"
            j["path"] = ss.get("xhttpSettings", {}).get("path", "/")
            j["host"] = ss.get("xhttpSettings", {}).get("host", "")
        elif net == "grpc":
            j["net"] = "grpc"
            j["path"] = ss.get("grpcSettings", {}).get("serviceName", "")
        elif net == "h2":
            j["path"] = ss.get("httpSettings", {}).get("path", "/")
            j["host"] = ",".join(ss.get("httpSettings", {}).get("host", []))
        elif net == "tcp":
            is_http, req = _tcp_http(ss)
            if is_http:
                j["type"] = "http"
                j["path"] = (req.get("path") or ["/"])[0]
                j["host"] = ",".join(req.get("headers", {}).get("Host", []) or [])
        if sec == "tls":
            j["tls"] = "tls"
            j["sni"] = ss.get("tlsSettings", {}).get("serverName", "")
            if ss.get("tlsSettings", {}).get("alpn"):
                j["alpn"] = ",".join(ss["tlsSettings"]["alpn"])
        return "vmess://" + b64(json.dumps(j, ensure_ascii=False))

    if p == "vless":
        v = ob["settings"]["vnext"][0]
        u = v["users"][0]
        q = {"encryption": "none", "type": net}
        if sec in ("tls", "reality"):
            q["security"] = sec
            q["sni"] = (ss.get("tlsSettings") or ss.get("realitySettings") or {}).get("serverName", "")
            if sec == "reality":
                rs = ss["realitySettings"]
                q["fp"] = rs.get("fingerprint", "chrome")
                q["pbk"] = rs.get("publicKey", "")
                q["sid"] = rs.get("shortId", "")
            else:
                ts = ss.get("tlsSettings") or {}
                if ts.get("fingerprint"):
                    q["fp"] = ts["fingerprint"]
                if ts.get("alpn"):
                    q["alpn"] = ",".join(ts["alpn"])
        if u.get("flow"):
            q["flow"] = u["flow"]
        if net in ("ws", "httpupgrade"):
            q["path"] = ss.get("wsSettings", {}).get("path", "/")
            h = ss.get("wsSettings", {}).get("headers", {}).get("Host", "")
            if h:
                q["host"] = h
        elif net in ("xhttp", "splithttp"):
            q["type"] = "xhttp"
            x = ss.get("xhttpSettings", {})
            q["path"] = x.get("path", "/")
            if x.get("host"):
                q["host"] = x["host"]
        elif net == "grpc":
            q["serviceName"] = ss.get("grpcSettings", {}).get("serviceName", "")
        elif net == "h2":
            q["path"] = ss.get("httpSettings", {}).get("path", "/")
            q["host"] = ",".join(ss.get("httpSettings", {}).get("host", []))
        elif net == "tcp":
            is_http, req = _tcp_http(ss)
            if is_http:
                q["headerType"] = "http"
                q["path"] = (req.get("path") or ["/"])[0]
                q["host"] = ",".join(req.get("headers", {}).get("Host", []) or [])
        return "vless://%s@%s:%d?%s#%s" % (u["id"], v["address"], v["port"],
                                           urllib.parse.urlencode(q, safe="/"), remark)

    if p == "trojan":
        s = ob["settings"]["servers"][0]
        q = {"type": net}
        if sec == "tls":
            q["security"] = "tls"
            q["sni"] = ss.get("tlsSettings", {}).get("serverName", "")
        if net in ("ws", "httpupgrade"):
            q["path"] = ss.get("wsSettings", {}).get("path", "/")
            h = ss.get("wsSettings", {}).get("headers", {}).get("Host", "")
            if h:
                q["host"] = h
        elif net == "grpc":
            q["serviceName"] = ss.get("grpcSettings", {}).get("serviceName", "")
        elif net == "tcp":
            is_http, req = _tcp_http(ss)
            if is_http:
                q["headerType"] = "http"
                q["path"] = (req.get("path") or ["/"])[0]
                q["host"] = ",".join(req.get("headers", {}).get("Host", []) or [])
        return "trojan://%s@%s:%d?%s#%s" % (urllib.parse.quote(s["password"], safe=""),
                                           s["address"], s["port"],
                                           urllib.parse.urlencode(q, safe="/"), remark)

    if p == "shadowsocks":
        s = ob["settings"]["servers"][0]
        raw = b64("%s:%s" % (s["method"], s["password"]))
        user = raw.rstrip("=").replace("+", "-").replace("/", "_")
        return "ss://%s@%s:%d#%s" % (user, s["address"], s["port"], remark)

    return None


def load_uniq():
    verified = json.load(open(os.path.join(WORK, "stable.json")))
    verified.sort(key=lambda n: n.get("proxy_ms", 9999))
    seen, uniq = set(), []
    for n in verified:
        k = json.dumps(n["outbound"], sort_keys=True)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
    return uniq


def main():
    import pipeline as P
    uniq = load_uniq()
    lines, bad = [], []
    for i, n in enumerate(uniq, 1):
        link = rebuild(n, i)
        if link:
            lines.append(link)
            ob = P.parse_node(link)
            if not ob or P.fingerprint(ob) != P.fingerprint(n["outbound"]):
                bad.append((i, n["proto"], link))
    for i, proto, link in bad:
        print("!! 重建不一致 #%d %s %s" % (i, proto, link[:80]))
    print("一致性校验: %d/%d 通过" % (len(lines) - len(bad), len(lines)))
    ts = time.strftime("%Y%m%d_%H%M")
    os.makedirs(OUT_DIR, exist_ok=True)
    txt_path = os.path.join(OUT_DIR, "v2rayN可用节点_%s.txt" % ts)
    b64_path = os.path.join(OUT_DIR, "v2rayN可用节点_%s_base64订阅.txt" % ts)
    content = "\n".join(lines)
    open(txt_path, "w", encoding="utf-8").write(content + "\n")
    open(b64_path, "w", encoding="utf-8").write(b64(content) + "\n")
    proto = {}
    for n in uniq:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    json.dump({"count": len(lines), "proto": proto, "txt": txt_path, "b64": b64_path, "ts": ts},
              open(os.path.join(WORK, "out_meta.json"), "w"), ensure_ascii=False)
    print("输出可用节点: %d  协议: %s" % (len(lines), proto))
    print("文件: %s" % txt_path)
    print("文件: %s" % b64_path)


if __name__ == "__main__":
    main()
