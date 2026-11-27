#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""终检定稿：一致性校验 -> 导出前连测两轮 -> 写文件"""
import base64, json, os, sys, time
import pipeline as P
import build2 as B

WORK = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "/home/user/Doubao/chats/38452101219217922"
TS = time.strftime("%Y%m%d_%H%M")


def b64(s):
    return base64.b64encode(s.encode()).decode()


def probe_set(nodes, timeout, label, port0):
    passed = []
    for i in range(0, len(nodes), 100):
        batch = nodes[i:i + 100]
        res = P.run_batch(batch, port0 + (i // 100) * 100, timeout=timeout, workers=40)
        for n, ms in zip(batch, res):
            if ms:
                n["proxy_ms"] = ms
                passed.append(n)
        print("  %s: 通过 %d/%d, 累计 %d" % (label, sum(1 for r in res if r), len(batch), len(passed)), flush=True)
    return passed


def main():
    uniq = B.load_uniq()
    good = []
    for n in uniq:
        link = B.rebuild(n, 1)
        ob = P.parse_node(link) if link else None
        if ob and P.fingerprint(ob) == P.fingerprint(n["outbound"]):
            good.append(n)
    print("一致性校验通过: %d/%d" % (len(good), len(uniq)))
    nodes = good
    for rnd in (1, 2):
        nodes = probe_set(nodes, 10.0, "终检第%d轮" % rnd, 62000)
        if rnd == 2:
            break
    if not nodes:
        print("无可用节点")
        sys.exit(1)
    nodes.sort(key=lambda n: n.get("proxy_ms", 9999))
    lines = [B.rebuild(n, i) for i, n in enumerate(nodes, 1)]
    lines = [l for l in lines if l]
    os.makedirs(OUT_DIR, exist_ok=True)
    txt = os.path.join(OUT_DIR, "v2rayN可用节点_%s.txt" % TS)
    b64p = os.path.join(OUT_DIR, "v2rayN可用节点_%s_base64订阅.txt" % TS)
    content = "\n".join(lines)
    open(txt, "w", encoding="utf-8").write(content + "\n")
    open(b64p, "w", encoding="utf-8").write(b64(content) + "\n")
    proto = {}
    for n in nodes:
        proto[n["proto"]] = proto.get(n["proto"], 0) + 1
    json.dump({"count": len(lines), "proto": proto, "txt": txt, "b64": b64p, "ts": TS,
               "ms": [n.get("proxy_ms") for n in nodes]},
              open(os.path.join(WORK, "final_meta.json"), "w"), ensure_ascii=False)
    print("定稿: %d 条 %s" % (len(lines), proto))
    print("文件: %s" % txt)
    # 自动发布到 GitHub 仓库并刷新 CDN（失败不影响本地成品）
    saved_argv = sys.argv
    try:
        import publish
        sys.argv = [saved_argv[0], OUT_DIR]
        publish.main()
    except SystemExit as e:
        print("发布中断: %s" % e)
    except Exception as e:
        print("发布失败: %s" % e)
    finally:
        sys.argv = saved_argv


if __name__ == "__main__":
    main()
