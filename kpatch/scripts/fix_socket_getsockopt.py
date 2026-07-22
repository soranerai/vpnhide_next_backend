#!/usr/bin/env python3
import sys

def fix_getsockopt(lines):
    func_start = None
    for i, line in enumerate(lines):
        if 'int __sys_getsockopt(' in line:
            func_start = i
            break

    if func_start is None:
        print("ERROR: __sys_getsockopt not found in socket.c")
        return lines

    target_idx = None
    for i in range(func_start, len(lines)):
        if i > func_start and (lines[i].startswith('SYSCALL_DEFINE5(getsockopt') or lines[i].startswith('COMPAT_SYSCALL_DEFINE5(getsockopt')):
            for j in range(i - 1, func_start, -1):
                if 'fput_light(' in lines[j]:
                    target_idx = j
                    break
            break

    if target_idx is None:
        for i in range(func_start, len(lines)):
            if 'fput_light(' in lines[i]:
                target_idx = i
                break

    if target_idx is None:
        print("ERROR: fput_light not found inside __sys_getsockopt")
        return lines

    # Check if getsockopt hook is already present
    hook_present = False
    for i in range(max(0, target_idx - 5), min(len(lines), target_idx + 5)):
        if 'vpnhide_getsockopt' in lines[i]:
            hook_present = True
            break

    if not hook_present:
        print(f"Injecting getsockopt hook right before fput_light at line {target_idx + 1}")
        hook = [
            "\n",
            "#ifdef CONFIG_VPNHIDE\n",
            "\tvpnhide_getsockopt(sock, level, optname, optval, optlen, &err);\n",
            "#endif\n"
        ]
        lines = lines[:target_idx] + hook + lines[target_idx:]
        print("getsockopt hook successfully injected.")
    else:
        print("getsockopt hook already present, skipping.")

    return lines


def fix_setsockopt(lines):
    func_start = None
    for i, line in enumerate(lines):
        if 'int __sys_setsockopt(' in line:
            func_start = i
            break

    if func_start is None:
        print("WARNING: __sys_setsockopt not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if lines[i].startswith('SYSCALL_DEFINE5(setsockopt') or lines[i].startswith('COMPAT_SYSCALL_DEFINE5(setsockopt') or lines[i].startswith('SYSCALL_DEFINE') or lines[i].startswith('int do_sock_getsockopt'):
            func_end = i
            break

    for i in range(func_start, func_end):
        if 'vpnhide_setsockopt' in lines[i]:
            print("setsockopt hook already present, skipping.")
            return lines

    target_idx = None
    # 1. Check for newer 6.6 sublevel pattern: do_sock_setsockopt
    for i in range(func_start, func_end):
        if 'err = do_sock_setsockopt(' in lines[i]:
            target_idx = i
            break

    # 2. Check for older 6.6 / 5.10 / 5.15 / 6.1 pattern: if (kernel_optval) or sock_use_custom_sol_socket
    if target_idx is None:
        for i in range(func_start, func_end):
            if 'if (kernel_optval)' in lines[i]:
                if i + 1 < func_end and 'optval =' in lines[i + 1]:
                    target_idx = i + 2
                else:
                    target_idx = i + 1
                break
            elif 'sock_use_custom_sol_socket' in lines[i] or 'sock_setsockopt(' in lines[i]:
                target_idx = i
                break

    # 3. Fallback: right before fput_light in __sys_setsockopt
    if target_idx is None:
        for i in range(func_start, func_end):
            if 'fput_light(' in lines[i]:
                target_idx = i
                break

    if target_idx is None:
        print("ERROR: could not determine injection point in __sys_setsockopt")
        return lines

    print(f"Injecting setsockopt hook at line {target_idx + 1}")
    hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        "\t{\n",
        "\t\tint _vret = vpnhide_setsockopt_sock(sock, level, optname, optval, optlen);\n",
        "\t\tif (_vret) {\n",
        "\t\t\terr = (_vret > 0) ? 0 : _vret;\n",
        "\t\t\tfput_light(sock->file, fput_needed);\n",
        "\t\t\treturn err;\n",
        "\t\t}\n",
        "\t}\n",
        "#endif\n"
    ]
    lines = lines[:target_idx] + hook + lines[target_idx:]
    print("setsockopt hook successfully injected.")
    return lines


def main():
    if len(sys.argv) < 2:
        print("Usage: fix_socket_getsockopt.py <socket.c path> [--setsockopt]")
        sys.exit(1)

    file_path = sys.argv[1]
    do_setsockopt = "--setsockopt" in sys.argv[2:]

    with open(file_path, 'r') as f:
        lines = f.readlines()

    lines = fix_getsockopt(lines)
    if do_setsockopt:
        lines = fix_setsockopt(lines)

    with open(file_path, 'w') as f:
        f.writelines(lines)

if __name__ == "__main__":
    main()
