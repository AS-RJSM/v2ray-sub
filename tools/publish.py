#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把当日成品推送到 GitHub 仓库（sub.txt）并刷新 jsDelivr 缓存。
可独立运行：  python3 publish.py [输出目录]
"""
import base64, glob, json, os, sys, time
import urllib.request, urllib.error

REPO = "AS-RJSM/v2ray-sub"
FILE_PATH = "sub.txt"
BRANCH = "main"
CDN = "https://cdn.jsdelivr.net/gh/%s@%s/%s" % (REPO, BRANCH, FILE_PATH)
PURGE = "https://purge.jsdelivr.net/gh/%s@%s/%s" % (REPO, BRANCH, FILE_PATH)

DEF_DIRS = [
    r"F:\Tools\NetTools\V2RAYN地址",
    os.path.expanduser("~/Doubao/chats/38452101219217922"),
    "/home/user/Doubao/chats/38452101219217922",
]
TOKEN_FILES = [
    os.path.expanduser("~/.v2ray_sub_token"),
    r"F:\Tools\NetTools\.gh_token.txt",
    os.path.join(os.environ.get("TEMP", "/tmp"), "gh_token.txt"),
    "/home/user/v2rayharvest/.gh_token.txt",
]


def out_dir():
    if len(sys.argv) > 1:
        return sys.argv[1]
    for d in DEF_DIRS:
        if os.path.isdir(d):
            return d
    raise SystemExit("找不到输出目录")


def token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t.strip()
    for p in TOKEN_FILES:
        if os.path.isfile(p):
            v = open(p, encoding="utf-8").read().strip()
            if "=" in v and "\n" in v:
                continue
            if v:
                return v
    raise SystemExit("没有可用的 GitHub 令牌")


def newest_pair(d):
    base = sorted(glob.glob(os.path.join(d, "v2rayN可用节点_*_base64订阅.txt")),
                  key=os.path.getmtime)
    if not base:
        raise SystemExit("目录内没有成品：%s" % d)
    b = base[-1]
    txt = b.replace("_base64订阅.txt", ".txt")
    return txt, b


def cleanup(d, keep):
    removed = []
    for f in glob.glob(os.path.join(d, "v2rayN*")):
        if os.path.abspath(f) not in [os.path.abspath(k) for k in keep]:
            os.remove(f)
            removed.append(os.path.basename(f))
    return removed


def api(method, url, tok, data=None):
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "doubao-agent")
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, body, timeout=45) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        raise RuntimeError("HTTP %s: %s" % (e.code, raw[:400]))


def get_url(url, timeout=35):
    req = urllib.request.Request(url)
    req.add_header("Cache-Control", "no-cache")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()


def main():
    d = out_dir()
    txt, b64p = newest_pair(d)
    content = open(b64p, encoding="utf-8").read().strip()
    print("成品: %s (%d 字节)" % (os.path.basename(txt), os.path.getsize(txt)))

    removed = cleanup(d, [txt, b64p])
    if removed:
        print("清理历史文件: %s" % ", ".join(removed))

    tok = token()
    url = "https://api.github.com/repos/%s/contents/%s" % (REPO, FILE_PATH)
    sha = None
    try:
        info = api("GET", url + "?ref=" + BRANCH, tok)
        sha = info.get("sha")
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            raise

    payload = {
        "message": "Update subscription " + time.strftime("%Y-%m-%d %H:%M"),
        "content": base64.b64encode(content.encode()).decode(),
        "branch": BRANCH,
    }
    if sha:
        payload["sha"] = sha
    res = api("PUT", url, tok, payload)
    print("已推送 GitHub: %s" % res.get("commit", {}).get("sha"))

    try:
        print("刷新 CDN: %s" % get_url(PURGE)[:80].replace("\n", " "))
    except Exception as e:
        print("CDN 刷新失败(不影响): %s" % e)

    ok = False
    for i in range(6):
        try:
            remote = get_url(CDN).strip()
            if remote == content:
                ok = True
                break
        except Exception as e:
            print("校验重试 %d: %s" % (i + 1, e))
        time.sleep(10)
    print("CDN 内容一致: %s" % ok)
    print("订阅地址: %s" % CDN)
    if not ok:
        sys.exit(2)


if __name__ == "__main__":
    main()
