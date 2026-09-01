# red-evasions

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PoC](https://img.shields.io/badge/PoC-runnable-blue.svg)](#技术分类)

**红队绕过技术库** —— 每个技术都附带**可在本地模拟器上直接运行**的 PoC，
并给出对应的**检测 / 防御**要点。定位：学习与防御研究，不是武器库。

> ⚠️ 仅用于你拥有书面授权的目标、红蓝对抗演练或自有靶场。
> 对未授权系统使用可能违反《刑法》285/286、《网络安全法》及 CFAA。
> 本项目所有 PoC 均针对**本地模拟器**运行，不内置任何可对外攻击的载荷。

---

## 设计理念

很多"绕过技术"文章只讲攻击、不讲边界。本库坚持三条：

1. **可复现**：每个技术都有独立 `.py`，`python xxx.py` 即可看到绕过/拦截差异。
2. **双视角**：每个绕过都配"正确的防御怎么做"（WAF 归一化、输出编码、一致性解码、钩子完整性校验）。
3. **防御优先**：AMSI/ETW 类只提供**检测侧** PoC（只读内存特征扫描），不提供改写内存的利用。

## 技术分类

| 分类 | 技术 | PoC | 视角 |
|------|------|-----|------|
| WAF 绕过 | SQLi 注释/空白/编码绕过 | `waf-evasion/sqli_waf_bypass.py` | 攻击+防御 |
| WAF 绕过 | XSS 过滤器绕过（事件处理器/伪协议） | `waf-evasion/xss_filter_bypass.py` | 攻击+防御 |
| 编码滥用 | 双重 URL 解码路径遍历 | `encoding/url_double_decode.py` | 攻击+防御 |
| AMSI/ETW | AmsiScanBuffer 补丁检测 | `amsi-etw/detect_amsi_patch.py` | 仅防御（只读） |

## 运行

```powershell
cd red-evasions
python techniques/waf-evasion/sqli_waf_bypass.py
python techniques/waf-evasion/xss_filter_bypass.py
python techniques/encoding/url_double_decode.py
python techniques/amsi-etw/detect_amsi_patch.py   # Windows only
```

## 目录

```
red-evasions/
├─ techniques/
│  ├─ waf-evasion/    WAF/过滤器绕过（含本地模拟 WAF）
│  ├─ encoding/       编码与规范化滥用
│  └─ amsi-etw/       Windows AMSI/ETW（防御侧检测）
└─ README.md
```

## 新增技术规范

- 每个技术一个目录，含 `README.md`（原理 + 边界）+ 一个可运行 `*.py`
- PoC 必须针对**本地模拟器**，不发真实攻击请求
- 必须写明对应的检测/防御手段
- 不含任何可被直接拿来打未授权目标的完整利用链

---

仓库：https://github.com/kwekre/red-evasions
