"""
XSS 过滤器绕过 PoC（教学/本地模拟器）。

演示一个"只删 <script> 和 onerror=" 的幼稚过滤器为何拦不住其它事件处理器 /
标签 / 伪协议；并给出正确的输出编码修复。

仅用于授权目标或自有靶场。运行：python xss_filter_bypass.py
"""
import re


def naive_xss_filter(html: str) -> str:
    """幼稚过滤器：删掉 <script...> 和 onerror= 属性。"""
    s = re.sub(r"<script.*?>", "", html, flags=re.I)
    s = re.sub(r"onerror\s*=", "", s, flags=re.I)  # 注意：只处理 onerror
    return s


def safe_encode(value: str) -> str:
    """正确做法：输出到 HTML 处做实体编码。"""
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


# (技术名, 恶意输入, 幼稚过滤器是否仍会渲染出危险标签)
PAYLOADS = [
    ("<script> 直连",        "<script>alert(1)</script>"),
    ("img onerror",          "<img src=x onerror=alert(1)>"),
    ("svg onload",           "<svg/onload=alert(1)>"),
    ("details ontoggle",     "<details open ontoggle=alert(1)>"),
    ("body onload",          "<body onload=alert(1)>"),
    ("javascript: 伪协议",   "<a href=javascript:alert(1)>x</a>"),
    ("iframe srcdoc",        "<iframe srcdoc='<script>alert(1)</script>'>"),
]


def main():
    print("== 幼稚 XSS 过滤器（删 <script> / onerror=）==")
    for name, payload in PAYLOADS:
        cleaned = naive_xss_filter(payload)
        dangerous = bool(re.search(r"<(svg|details|body|iframe|a|img)",
                                   cleaned, re.I)) or "javascript:" in cleaned
        print(f"  [{'危险' if dangerous else '安全'}] {name:<20} -> {cleaned}")

    print("\n== 正确做法：输出实体编码 ==")
    for name, payload in PAYLOADS[:3]:
        print(f"  {name:<20} -> {safe_encode(payload)}")

    print("\n结论：基于黑名单的过滤器总有漏网；"
          "上下文感知的输出编码（HTML/JS/URL/Attribute 分别处理）+ CSP 才是正解。")


if __name__ == "__main__":
    main()
