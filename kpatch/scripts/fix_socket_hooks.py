#!/usr/bin/env python3
# Structure-aware injection of VPNHide hooks into net/socket.c.
#
# Why not a context diff: android16-6.12 spans both the GKI tree (still using
# sockfd_lookup_light()/fput_light()) and a "6.12 LTS"-style tree that has
# picked up the upstream CLASS(fd, f) scoped-fd refactor (sock_from_file()/
# fd_empty(f), early returns instead of goto). The two shapes differ enough
# that a context-diff hunk either hard-fails or, worse, silently mis-applies
# via `patch --fuzz` (a hunk with only 2-3 lines of context on each side can
# match "close enough" at the wrong location once fuzz absorbs all of it).
# These functions instead anchor on stable literal markers and adapt to
# whichever shape is present.
import re
import sys


def _find_function(lines, needle, start=0):
    for i in range(start, len(lines)):
        if lines[i].startswith(needle):
            return i
    return None


def _leading_ws(line):
    return line[: len(line) - len(line.lstrip())]


_DECL_KEYWORDS = (
    "struct ",
    "union ",
    "enum ",
    "unsigned ",
    "signed ",
    "const ",
    "static ",
    "int ",
    "long ",
    "short ",
    "char ",
    "void ",
    "bool ",
    "size_t ",
    "ssize_t ",
    "sockptr_t ",
    "u8 ",
    "u16 ",
    "u32 ",
    "u64 ",
    "s8 ",
    "s16 ",
    "s32 ",
    "s64 ",
)


def _looks_like_decl(line):
    """True for a leading local declaration, a blank line, or a comment --
    i.e. lines that are safe to walk past when looking for the first real
    statement in a function (kernel builds error on -Wdeclaration-after-
    statement, so hooks must never land before the tail of a decl block)."""
    s = line.strip()
    if not s:
        return True
    if s.startswith("/*") or s.startswith("//") or s.startswith("*"):
        return True
    if s.startswith("CLASS("):
        return True
    return any(s.startswith(kw) for kw in _DECL_KEYWORDS)


def _statement_span(lines, start_idx, open_marker):
    """Given the line where a call statement starting with `open_marker`
    begins, return (start_idx, end_idx) spanning every line needed for
    the parens to balance back to zero (handles multi-line call args)."""
    depth = 0
    started = False
    for i in range(start_idx, len(lines)):
        text = lines[i][lines[i].index(open_marker) :] if i == start_idx else lines[i]
        for ch in text:
            if ch == "(":
                depth += 1
                started = True
            elif ch == ")":
                depth -= 1
        if started and depth == 0:
            return start_idx, i
    return start_idx, start_idx


def fix_bind(lines):
    func_start = _find_function(lines, "int __sys_bind_socket(")
    if func_start is None:
        print("ERROR: __sys_bind_socket not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if lines[i].startswith("int __sys_bind("):
            func_end = i
            break

    if any("vpnhide_bind_post" in lines[i] for i in range(func_start, func_end)):
        print("bind hook already present, skipping.")
        return lines

    target_idx = None
    for i in range(func_start, func_end):
        if "READ_ONCE(sock->ops)->bind(sock," in lines[i]:
            target_idx = i
            break
    if target_idx is None:
        print("ERROR: could not find bind() call in __sys_bind_socket")
        return lines

    guard_idx = target_idx - 1
    if "if (!err)" not in lines[guard_idx]:
        print(
            "ERROR: unexpected code shape before bind() call, aborting bind hook injection"
        )
        return lines

    stmt_end = target_idx
    while ");" not in lines[stmt_end]:
        stmt_end += 1

    guard_indent = _leading_ws(lines[guard_idx])
    lines[guard_idx] = (
        lines[guard_idx].rstrip("\n").replace("if (!err)", "if (!err) {") + "\n"
    )

    hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        "\t\tvpnhide_bind_pre(sock, (struct sockaddr *)address, addrlen);\n",
        "#endif\n",
    ]
    post_hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        "\t\tvpnhide_bind_post(sock, err);\n",
        "#endif\n",
    ]
    lines = (
        lines[:target_idx]
        + hook
        + lines[target_idx : stmt_end + 1]
        + post_hook
        + [guard_indent + "}\n"]
        + lines[stmt_end + 1 :]
    )
    print(f"bind hooks injected around bind() call at line {target_idx + 1}")
    return lines


def fix_listen(lines):
    func_start = _find_function(lines, "int __sys_listen_socket(")
    if func_start is None:
        func_start = _find_function(lines, "int __sys_listen(")
    if func_start is None:
        print("ERROR: listen implementation not found in socket.c")
        return lines

    func_end = min(len(lines), func_start + 160)
    if any("vpnhide_listen_post" in lines[i] for i in range(func_start, func_end)):
        print("listen hook already present, skipping.")
        return lines

    target_idx = None
    for i in range(func_start, func_end):
        if "->listen(sock," in lines[i]:
            target_idx = i
            break
    if target_idx is None:
        print("ERROR: could not find listen() call")
        return lines

    _, stmt_end = _statement_span(lines, target_idx, "listen(")
    indent = _leading_ws(lines[target_idx])
    hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        f"{indent}vpnhide_listen_post(sock, err);\n",
        "#endif\n",
    ]
    lines = lines[: stmt_end + 1] + hook + lines[stmt_end + 1 :]
    print(f"listen post-hook injected after line {stmt_end + 1}")
    return lines


def fix_connect(lines):
    func_start = _find_function(lines, "int __sys_connect(")
    if func_start is None:
        print("ERROR: __sys_connect not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if lines[i].startswith("SYSCALL_DEFINE"):
            func_end = i
            break

    if any("vpnhide_connect(" in lines[i] for i in range(func_start, func_end)):
        print("connect hook already present, skipping.")
        return lines

    brace_idx = None
    for i in range(func_start, min(func_start + 4, len(lines))):
        if lines[i].strip() == "{":
            brace_idx = i
            break
    if brace_idx is None:
        print("ERROR: could not find opening brace of __sys_connect")
        return lines

    # Kernel builds treat mixing declarations and statements as an error
    # (-Wdeclaration-after-statement -Werror), so the hook can't just go
    # right after the opening brace -- it has to land after whatever local
    # declarations the function's own shape has (2 lines in the old
    # sockfd_lookup_light-era style, up to 4 in the CLASS(fd) style).
    # Walk forward skipping blank/comment lines and anything that looks
    # like a declaration, rather than hardcoding a line count.
    insert_idx = brace_idx + 1
    while insert_idx < func_end and _looks_like_decl(lines[insert_idx]):
        insert_idx += 1

    # struct fd's raw `.file` member became inaccessible once the kernel's
    # fd-refcounting rework (which packs flags into the pointer) landed --
    # from that point on you MUST go through the fd_file() accessor. Older
    # trees don't have fd_file() at all. Detect which shape this tree is by
    # checking whether fd_file( appears anywhere in the file, rather than
    # hardcoding it per KMI version (that's what made the 6.12 patch brittle
    # in the first place -- the same drift can happen on any branch).
    full_text = "".join(lines)
    fd_expr = "fd_file(_f)" if "fd_file(" in full_text else "_f.file"

    # sock_from_file() used to take an `int *err` out-param on older trees
    # (e.g. 5.10) and was simplified to a single arg later. Its own
    # definition is always present in this file, so sniff the arity there
    # instead of hardcoding per version.
    arity = 1
    m = re.search(r"sock_from_file\(([^)]*)\)", full_text)
    if m:
        params = [p for p in m.group(1).split(",") if p.strip()]
        if len(params) >= 2:
            arity = 2

    pre_decl = []
    if arity == 2:
        sock_from_file_call = f"sock_from_file({fd_expr}, &_err)"
        pre_decl = ["\t\t\tint _err = 0;\n"]
    else:
        sock_from_file_call = f"sock_from_file({fd_expr})"

    # Fully self-contained: does its own fdget()/fdput(), so it doesn't
    # depend on whatever local variables the surrounding function shape
    # declares (old sockfd_lookup_light style vs. new CLASS(fd, f) style).
    hook = (
        [
            "#ifdef CONFIG_VPNHIDE\n",
            "\t{\n",
            "\t\tstruct fd _f = fdget(fd);\n",
            f"\t\tif ({fd_expr}) {{\n",
        ]
        + pre_decl
        + [
            f"\t\t\tstruct socket *_sock = {sock_from_file_call};\n",
            "\t\t\tif (_sock) {\n",
            "\t\t\t\tint _ret = 0;\n",
            "\t\t\t\tif (vpnhide_connect(_sock, uservaddr, addrlen, &_ret)) {\n",
            "\t\t\t\t\tfdput(_f);\n",
            "\t\t\t\t\treturn _ret;\n",
            "\t\t\t\t}\n",
            "\t\t\t}\n",
            "\t\t\tfdput(_f);\n",
            "\t\t}\n",
            "\t}\n",
            "#endif\n",
        ]
    )
    lines = lines[:insert_idx] + hook + lines[insert_idx:]
    print(
        f"connect hook injected after leading declarations at line {insert_idx + 1} "
        f"(fd_expr={fd_expr}, sock_from_file arity={arity})"
    )
    return lines


def fix_getname(lines, func_needle, peer_flag):
    func_start = _find_function(lines, func_needle)
    if func_start is None:
        print(f"ERROR: {func_needle.strip()} not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if lines[i].startswith("SYSCALL_DEFINE"):
            func_end = i
            break

    hook_marker = f"vpnhide_getname(sock, (struct sockaddr *)&address, {peer_flag},"
    if any(hook_marker in lines[i] for i in range(func_start, func_end)):
        print(f"{func_needle.strip()} getname hook already present, skipping.")
        return lines

    call_needle = f"getname(sock, (struct sockaddr *)&address, {peer_flag});"
    call_idx = None
    for i in range(func_start, func_end):
        if call_needle in lines[i]:
            call_idx = i
            break
    if call_idx is None:
        print(
            f"ERROR: getname(peer={peer_flag}) call not found in {func_needle.strip()}"
        )
        return lines

    move_idx = None
    for i in range(call_idx, func_end):
        if "move_addr_to_user(&address, err, usockaddr" in lines[i]:
            move_idx = i
            break
    if move_idx is None:
        print(
            f"ERROR: move_addr_to_user() not found after getname() in {func_needle.strip()}"
        )
        return lines

    stmt_end = move_idx
    while ";" not in lines[stmt_end]:
        stmt_end += 1

    # Nearest 'if (' between the getname() call and move_addr_to_user() tells
    # us the shape: "if (err >= 0)" as an unbraced single-statement guard
    # directly wrapping move_addr_to_user() (old getpeername shape) vs.
    # "if (err < 0) return err;"/"goto out_put;" early-exit-on-failure,
    # after which move_addr_to_user() runs unconditionally (getsockname in
    # both shapes, and getpeername in the CLASS(fd)/LTS shape).
    guard_idx = None
    for i in range(call_idx + 1, move_idx):
        if lines[i].strip().startswith("if ("):
            guard_idx = i
    wraps_success = (
        guard_idx is not None
        and ">= 0" in lines[guard_idx]
        and not lines[guard_idx].rstrip().endswith("{")
    )

    move_indent = _leading_ws(lines[move_idx])
    hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        f"{move_indent}vpnhide_getname(sock, (struct sockaddr *)&address, {peer_flag}, &err);\n",
        "#endif\n",
    ]

    if wraps_success:
        guard_indent = _leading_ws(lines[guard_idx])
        lines[guard_idx] = lines[guard_idx].rstrip("\n") + " {\n"
        lines = (
            lines[: call_idx + 1]
            + lines[call_idx + 1 : move_idx]
            + hook
            + lines[move_idx : stmt_end + 1]
            + [guard_indent + "}\n"]
            + lines[stmt_end + 1 :]
        )
        print(
            f"getname(peer={peer_flag}) hook injected (braced) before move_addr_to_user at line {move_idx + 1}"
        )
    else:
        lines = lines[:move_idx] + hook + lines[move_idx:]
        print(
            f"getname(peer={peer_flag}) hook injected before move_addr_to_user at line {move_idx + 1}"
        )

    return lines


def fix_getsockopt(lines):
    func_start = None
    for i, line in enumerate(lines):
        if "int __sys_getsockopt(" in line:
            func_start = i
            break

    if func_start is None:
        print("ERROR: __sys_getsockopt not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if lines[i].startswith("SYSCALL_DEFINE"):
            func_end = i
            break

    if any("vpnhide_getsockopt" in lines[i] for i in range(func_start, func_end)):
        print("getsockopt hook already present, skipping.")
        return lines

    # Shape 1 (GKI, sockfd_lookup_light/fput_light): separate `err` var,
    # post-hook right before the fput_light() release.
    target_idx = None
    for i in range(func_start, func_end):
        if "fput_light(" in lines[i]:
            target_idx = i
            break

    if target_idx is not None:
        print(
            f"Injecting getsockopt hook right before fput_light at line {target_idx + 1}"
        )
        hook = [
            "\n",
            "#ifdef CONFIG_VPNHIDE\n",
            "\tvpnhide_getsockopt(sock, level, optname, optval, optlen, &err);\n",
            "#endif\n",
        ]
        lines = lines[:target_idx] + hook + lines[target_idx:]
        print("getsockopt hook successfully injected.")
        return lines

    # Shape 2 (CLASS(fd, f) scoped cleanup): `return do_sock_getsockopt(...);`
    # directly, no separate err var and nothing to fput -- capture the
    # return value ourselves so the post-hook can still see/mutate it.
    call_idx = None
    for i in range(func_start, func_end):
        if "return do_sock_getsockopt(" in lines[i]:
            call_idx = i
            break

    if call_idx is None:
        print(
            "ERROR: neither fput_light() nor 'return do_sock_getsockopt(' found inside __sys_getsockopt"
        )
        return lines

    start_idx, end_idx = _statement_span(lines, call_idx, "do_sock_getsockopt(")
    indent = _leading_ws(lines[start_idx])
    # Wrapped in its own { } scope: `int _vh_err = ...` must be the first
    # statement of a fresh block, not a declaration slipped in after the
    # `if (fd_empty(f)) ...`/`if (unlikely(!sock)) ...` statements earlier
    # in the function -- kernel builds error on -Wdeclaration-after-statement.
    call_text = "".join(l.strip() + " " for l in lines[start_idx : end_idx + 1]).strip()
    call_text = call_text.replace(
        "return do_sock_getsockopt(", "do_sock_getsockopt(", 1
    )
    new_block = [
        f"{indent}{{\n",
        f"{indent}\tint _vh_err = {call_text}\n",
        f"{indent}#ifdef CONFIG_VPNHIDE\n",
        f"{indent}\tvpnhide_getsockopt(sock, level, optname, optval, optlen, &_vh_err);\n",
        f"{indent}#endif\n",
        f"{indent}\treturn _vh_err;\n",
        f"{indent}}}\n",
    ]
    lines = lines[:start_idx] + new_block + lines[end_idx + 1 :]
    print(f"getsockopt hook injected (CLASS(fd) shape) around line {start_idx + 1}")
    return lines


def fix_setsockopt(lines):
    func_start = None
    for i, line in enumerate(lines):
        if "int __sys_setsockopt(" in line:
            func_start = i
            break

    if func_start is None:
        print("WARNING: __sys_setsockopt not found in socket.c")
        return lines

    func_end = len(lines)
    for i in range(func_start + 1, len(lines)):
        if (
            lines[i].startswith("SYSCALL_DEFINE5(setsockopt")
            or lines[i].startswith("COMPAT_SYSCALL_DEFINE5(setsockopt")
            or lines[i].startswith("SYSCALL_DEFINE")
            or lines[i].startswith("int do_sock_getsockopt")
        ):
            func_end = i
            break

    for i in range(func_start, func_end):
        if "vpnhide_setsockopt" in lines[i]:
            print("setsockopt hook already present, skipping.")
            return lines

    # 0. CLASS(fd, f) scoped-cleanup shape: `return do_sock_setsockopt(...);`
    #    directly, no separate err var, nothing to fput_light -- the pre-hook
    #    just short-circuits with its own return before the real call.
    for i in range(func_start, func_end):
        if "return do_sock_setsockopt(" in lines[i]:
            indent = _leading_ws(lines[i])
            hook = [
                "#ifdef CONFIG_VPNHIDE\n",
                f"{indent}{{\n",
                f"{indent}\tint _vret = vpnhide_setsockopt_sock(sock, level, optname, optval, optlen);\n",
                f"{indent}\tif (_vret)\n",
                f"{indent}\t\treturn (_vret > 0) ? 0 : _vret;\n",
                f"{indent}}}\n",
                "#endif\n",
            ]
            lines = lines[:i] + hook + lines[i:]
            print(
                f"setsockopt hook injected (CLASS(fd) shape, pre-hook) before line {i + 1}"
            )
            return lines

    target_idx = None
    # 1. Check for newer 6.6 sublevel pattern: do_sock_setsockopt
    for i in range(func_start, func_end):
        if "err = do_sock_setsockopt(" in lines[i]:
            target_idx = i
            break

    # 2. Check for older 6.6 / 5.10 / 5.15 / 6.1 pattern: if (kernel_optval) or sock_use_custom_sol_socket
    if target_idx is None:
        for i in range(func_start, func_end):
            if "if (kernel_optval)" in lines[i]:
                if i + 1 < func_end and "optval =" in lines[i + 1]:
                    target_idx = i + 2
                else:
                    target_idx = i + 1
                break
            elif (
                "sock_use_custom_sol_socket" in lines[i]
                or "sock_setsockopt(" in lines[i]
            ):
                target_idx = i
                break

    # 3. Fallback: right before fput_light in __sys_setsockopt
    if target_idx is None:
        for i in range(func_start, func_end):
            if "fput_light(" in lines[i]:
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
        "#endif\n",
    ]
    lines = lines[:target_idx] + hook + lines[target_idx:]
    print("setsockopt hook successfully injected.")
    return lines


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: fix_socket_hooks.py <socket.c path> [--setsockopt] [--connect] [--bind-getname]"
        )
        sys.exit(1)

    file_path = sys.argv[1]
    flags = sys.argv[2:]
    do_setsockopt = "--setsockopt" in flags
    do_connect = "--connect" in flags
    do_bind_getname = "--bind-getname" in flags

    with open(file_path, "r") as f:
        lines = f.readlines()

    lines = fix_getsockopt(lines)
    if do_setsockopt:
        lines = fix_setsockopt(lines)
    if do_connect:
        lines = fix_connect(lines)
    lines = fix_listen(lines)
    if do_bind_getname:
        lines = fix_bind(lines)
        lines = fix_getname(lines, "int __sys_getsockname(", 0)
        lines = fix_getname(lines, "int __sys_getpeername(", 1)

    with open(file_path, "w") as f:
        f.writelines(lines)


if __name__ == "__main__":
    main()
