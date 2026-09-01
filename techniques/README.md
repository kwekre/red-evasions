# techniques/ 索引

每个子目录是一个绕过技术分类，内含 `README.md`（原理 + 边界）与可运行 PoC。

| 目录 | 主题 | 运行示例 |
|------|------|----------|
| [waf-evasion](waf-evasion/README.md) | WAF / 输入过滤器绕过 | `python waf-evasion/sqli_waf_bypass.py` |
| [encoding](encoding/README.md) | 编码与规范化滥用 | `python encoding/url_double_decode.py` |
| [amsi-etw](amsi-etw/README.md) | Windows AMSI / ETW（防御侧） | `python amsi-etw/detect_amsi_patch.py` |

**统一约束**：PoC 只打本地模拟器；不讲"怎么打真实站"；每个绕过都配防御。
