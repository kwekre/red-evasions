"""
AMSI 补丁检测 PoC（防御视角 / 只读 / Windows 专用）。

说明：红队常通过改写 amsi!AmsiScanBuffer 的前几个字节（典型为
`xor eax,eax; ret` = 33 C0 C3）来让所有脚本被判定为"干净"，从而绕过
AV/EDR 的脚本扫描。本脚本站在**防御侧**：读取当前进程内
AmsiScanBuffer 的前若干字节，比对是否被打了上述补丁特征。

仅做只读内存读取，不修改任何东西；非 Windows 平台直接跳过。
运行：python detect_amsi_patch.py
"""
import sys


# 经典补丁特征：函数开头被改成 xor eax,eax / ret
PATCHED_SIGNATURES = [
    bytes([0x33, 0xC0, 0xC3]),            # xor eax,eax; ret
    bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]),  # mov eax,0; ret
]


def scan() -> str:
    if sys.platform != "win32":
        return "当前非 Windows 平台，跳过（AMSI 仅存在于 Windows）。"

    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        h_mod = kernel32.GetModuleHandleW("amsi.dll")
        if not h_mod:
            return "未加载 amsi.dll（进程未触发 AMSI），无法检测。"
        addr = kernel32.GetProcAddress(h_mod, b"AmsiScanBuffer")
        if not addr:
            return "未找到 AmsiScanBuffer 导出。"

        # 读前 16 字节
        buf = ctypes.create_string_buffer(16)
        n = wintypes.DWORD(0)
        if not kernel32.ReadProcessMemory(kernel32.GetCurrentProcess(),
                                          addr, buf, 16, ctypes.byref(n)):
            return "ReadProcessMemory 失败（可能受保护）。"
        head = buf.raw[:16]

        for sig in PATCHED_SIGNATURES:
            if head.startswith(sig):
                return (f"[!] 检测到 AMSI 补丁特征 {sig.hex()} @ AmsiScanBuffer "
                        f"前 {len(sig)} 字节 —— AMSI 可能已被禁用。")
        return f"[+] 未检测到已知 AMSI 补丁特征。函数前 16 字节: {head.hex()}"
    except Exception as e:  # 权限/API 不可用等
        return f"检测中断: {e!r}"


def main():
    print("== AMSI 补丁检测（防御侧，只读）==")
    print(scan())
    print("\n检测只是事后取证。真正的防护是：EDR 对 AMSI 钩子做完整性校验、"
          "启用 AM SI 的进程注入防护、结合行为检测而非依赖单次扫描结果。")


if __name__ == "__main__":
    main()
