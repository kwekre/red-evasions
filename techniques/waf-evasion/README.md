# WAF / 输入过滤器绕过

WAF 本质是"在请求到达应用前做规则匹配"。规则越朴素（字面黑名单、不解码、不归一化），
越容易被构造的畸形输入绕过。

## 本目录 PoC

### 1. SQLi WAF 绕过 — `sqli_waf_bypass.py`
演示四类绕过幼稚 WAF（仅字面匹配 `union select`）的 payload：
- **内联注释**：`union/**/select` —— 注释切断关键字连续性
- **空白变异**：`union%09select` / `union%0aselect` —— Tab/换行替代空格
- **百分号编码**：`u%6eion%20select` —— 编码后字面不匹配
- **大小写混淆**：`UNION SELECT` —— 对"区分大小写"的过滤器有效（对大小写无关过滤器无效）

脚本同时给出"正确 WAF"：先 URL 解码 → 去注释 → 折叠空白，再匹配，四项全拦。

### 2. XSS 过滤器绕过 — `xss_filter_bypass.py`
演示只删 `<script>` 和 `onerror=` 的过滤器为何漏掉：
`<svg/onload>`、`<details ontoggle>`、`<body onload>`、`javascript:` 伪协议、`<iframe srcdoc>`。
并给出正确做法：上下文感知的输出实体编码 + CSP。

## 防御要点
- WAF 必须在匹配前做**规范化解码**（URL/HTML/Unicode）+ **去注释** + **空白折叠**
- 但 WAF 只是纵深防线，**根因修复是参数化查询与输出编码**
- 过滤器用白名单优于黑名单
