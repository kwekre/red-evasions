# Windows AMSI / ETW（防御侧）

AMSI（Antimalware Scan Interface）让脚本宿主（PowerShell、.NET、JS、VBA 等）把
待执行内容交给 AV/EDR 扫描。红队常用手法是把 `amsi!AmsiScanBuffer` 的前几个字节
补丁成 `xor eax,eax; ret`，让所有内容被判定为"干净"，从而绕过脚本扫描。

> 本目录**只提供检测侧 PoC，不提供任何改写内存的利用代码**。

## 本目录 PoC

### AmsiScanBuffer 补丁检测 — `detect_amsi_patch.py`
- 只读读取当前进程内 `AmsiScanBuffer` 的前 16 字节
- 比对已知补丁特征（`33 C0 C3` = `xor eax,eax; ret` 等）
- 命中即提示 AMSI 可能已被禁用；非 Windows / 未加载 amsi 时安全跳过
- 全程只读，不修改任何内存

## 防御要点
- EDR 对 AMSI/ETW 钩子做**完整性校验**（定期重读比对合法 prologue）
- 启用进程注入防护，阻止未签名代码改写安全 DLL
- 不依赖单次扫描结果，结合**行为检测**（进程树、异常子进程、网络外联）
- 关注 ETW 被 `ntdll!EtwNotificationRegister` 等手法 tamper 的同类检测
