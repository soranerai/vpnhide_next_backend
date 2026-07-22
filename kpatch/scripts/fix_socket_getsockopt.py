#!/usr/bin/env python3
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: fix_socket_getsockopt.py <socket.c path>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    with open(file_path, 'r') as f:
        lines = f.readlines()

    func_start = None
    for i, line in enumerate(lines):
        if 'int __sys_getsockopt(' in line:
            func_start = i
            break

    if func_start is None:
        print("ERROR: __sys_getsockopt not found in socket.c")
        sys.exit(1)

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
        sys.exit(1)

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
        with open(file_path, 'w') as f:
            f.writelines(lines)
        print("getsockopt hook successfully injected.")
    else:
        print("getsockopt hook already present, skipping.")

if __name__ == "__main__":
    main()
