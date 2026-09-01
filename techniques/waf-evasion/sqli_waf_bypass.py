"""
SQLi WAF 绕过 PoC（教学/本地模拟器）。

演示：一个"只做字面匹配、不解码不归一化"的幼稚 WAF 为什么拦不住
精心构造的 payload；以及正确的 WAF 应该如何做（先解码+去注释+折叠空白）。

仅用于你拥有授权的目标或自有靶场。运行：python sqli_waf_bypass.py
"""
import re
import urllib.parse


def naive_waf(payload: str, normalize: bool = False) -> tuple[bool, str]:
    """幼稚 WAF：字面子串匹配（默认不解码、不归一化）。"""
    p = payload
    if normalize:
        p = urllib.parse.unquote(p)              # 1) URL 解码
        p = re.sub(r"/\*.*?\*/", " ", p)          # 2) 去掉 /**/ 注释
        p = re.sub(r"\s+", " ", p)                # 3) 折叠所有空白为空格
    p = p.lower()
    if "union select" in p:
        return True, "命中 'union select' 字面规则"
    if "or 1=1" in p:
        return True, "命中 'or 1=1' 字面规则"
    return False, ""


# (技术名, payload, 预期在幼稚 WAF 下是否通过)
BYPASSES = [
    ("内联注释 union/**/select", "union/**/select", True),
    ("Tab 分隔 union\\tselect", "union%09select", True),
    ("换行分隔 union\\nselect", "union%0aselect", True),
    ("百分号编码 u%6eion select", "u%6eion%20select", True),
    ("大小写混淆 UNION SELECT", "UNION SELECT", False),   # 字面匹配(lower)仍命中
]


def main():
    print("== 幼稚 WAF（不解码、不归一化）==")
    passed = 0
    for name, payload, expect_pass in BYPASSES:
        blocked, why = naive_waf(payload, normalize=False)
        ok = (not blocked) == expect_pass
        passed += ok
        print(f"  [{'OK' if ok else 'XX'}] {name:<28} "
              f"{'被拦' if blocked else '通过'}  ({why or '无匹配'})")

    print("\n== 正确 WAF（先解码+去注释+折叠空白）==")
    for name, payload, _ in BYPASSES:
        blocked, why = naive_waf(payload, normalize=True)
        print(f"  [{'拦' if blocked else '漏'}] {name:<28} {why or '未拦截'}")

    print(f"\n结论：幼稚 WAF 下 {passed}/{len(BYPASSES)} 个绕过符合预期。"
          "真正有效的防御是参数化查询，WAF 只是纵深防线。")


if __name__ == "__main__":
    main()
