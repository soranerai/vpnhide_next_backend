# VPNHide Next

This repository provides two ways to integrate VPNHide with an Android kernel:

- `kmod` — an external KernelSU module (`vpnhide_kmod.ko`);
- `kpatch` — static integration of the driver directly into the kernel sources.

## Building kmod

`kmod/build.py` builds a ZIP module for the selected KMI. By default it uses the DDK container `ghcr.io/ylarod/ddk-min`. A local build therefore requires Docker or Podman and the Android NDK for building `vpnhide-ctl` and `vpnhide-daemon`.

```bash
# Build one variant (android14-6.1 by default)
./kmod/build.py --kmi android14-6.1

# Build all supported variants
./kmod/build.py --all
```

The resulting archive is written to the repository root:

```text
vpnhide-kmod-<kmi>.zip
```

The userspace daemon is kept in `daemon/`: `main.c` owns the event loop,
while network state, file hiding, statistics, owned ports, and config reloads
live in focused modules. The module build still packages it as
`vpnhide-daemon`.

Supported variants are: `android12-5.10`, `android13-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`, and `android17-6.18`.

The in-tree kpatch compatibility profiles additionally cover upstream 4.9.337, 4.14.336, 4.19.325, and Android common 5.4 (`upstream-4.9`, `upstream-4.14`, `upstream-4.19`, `android12-5.4`). Local QEMU matrices always run one build/container at a time. Test containers default to 32 compiler jobs with an 11 GiB hard memory limit; override these with `VPNHIDE_BUILD_JOBS` and `VPNHIDE_BUILD_MEMORY` for smaller hosts.

If the kernel sources and LLVM are already available locally, the container can be skipped:

```bash
./kmod/build.py \
  --kmi android14-6.1 \
  --kdir /path/to/kernel \
  --clang-dir /path/to/clang/bin
```

The KMI must match both the kernel sources and the target device. To install a built module on a connected rooted device:

```bash
./scripts/deploy-kmod.sh android14-6.1
```

The script checks the device KMI, builds the module, pushes it over ADB, and reboots the device.

### SUSFS path hiding

The daemon registers active VPN interface paths through SUSFS
`add_sus_path_loop`. This makes SUSFS re-apply the rules for each zygote-spawned
non-root process and for dynamic interface paths. Registration is also
repeated after an interface is recreated because SUSFS rules belong to the
current filesystem objects. If SUSFS or its command binary is
unavailable, the daemon continues operating and writes a rate-limited message
to `daemon.log`; the remaining kmod hooks are unaffected.

### NoMount path hiding

When `globalConfig.useNoMountForFileHiding` is `true`, the daemon uses the
installed NoMount module instead of SUSFS. It invokes
`/data/adb/modules/nomount/bin/nm rule add --whiteout <path>` for each active
VPN interface path and removes only rules it created when switching back to
SUSFS. NoMount must be installed and active; otherwise the daemon continues
without filesystem path hiding and logs the unavailable binary.

## Applying kpatch

`kpatch` does not produce a `.ko` file. It copies the driver into `security/vpnhide`, copies the public header into `include/linux`, and structurally injects the call sites for every supported profile, including legacy 4.9, 4.14, 4.19, and 5.4. VPNHide must then be built into the kernel with `CONFIG_VPNHIDE=y`.

The source tree must be clean before applying the integration:

```bash
./kpatch/scripts/apply.sh \
  /path/to/kernel/common \
  android14-6.1
```

Enable the following kernel configuration and build the kernel using the normal GKI/Kleaf workflow for that tree:

```text
CONFIG_VPNHIDE=y
```

The second argument to `apply.sh` selects the compatibility profile. The supported versions are the same as those listed above.

`upstream-4.9` is pinned to Linux `v4.9.337` and is intended for Android
kernel trees whose relevant networking code remains close to upstream 4.9.
Like the other legacy profiles, it is not a universal OEM profile: the structural injector deliberately
stops when a source shape differs instead of applying a fuzzy patch.

For a quick QEMU build and runtime check:

```bash
./kpatch/test/build-kernel.sh android14-6.1
./kpatch/test/run.sh android14-6.1
```

The legacy 4.9 QEMU gate is reproducible with:

```bash
./kpatch/test/build-kernel.sh upstream-4.9
./kpatch/test/run.sh upstream-4.9
```

Linux kernels before 4.16 lack the named-BPF-map ABI needed by the BPF laundering vector
and the UDP GSO (`UDP_SEGMENT`) API. The harness reports those two vectors as
`SKIP` for this profile; every vector supported by the kernel remains a
required pass.

To run the complete matrix sequentially, including clean builds for the
legacy 4.9, 4.14, 4.19, and 5.4 profiles:

```bash
./kpatch/test/run-local-container.sh
```

The test build uses the DDK container and stores the result at `kpatch/test/.cache/<kmi>/Image`. It is intended for validation and does not replace the vendor/GKI build workflow used for a production Android kernel.

## Русская версия

Репозиторий содержит два варианта интеграции VPNHide с Android-ядром:

- `kmod` — внешний KernelSU-модуль (`vpnhide_kmod.ko`);
- `kpatch` — статическая интеграция драйвера в исходники ядра.

### Сборка kmod

```bash
./kmod/build.py --kmi android14-6.1
./kmod/build.py --all
```

Архив `vpnhide-kmod-<kmi>.zip` появится в корне репозитория. Поддерживаются KMI: `android12-5.10`, `android13-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`, `android17-6.18`.

Для локальной сборки с уже установленными исходниками ядра и LLVM:

```bash
./kmod/build.py --kmi android14-6.1 \
  --kdir /path/to/kernel --clang-dir /path/to/clang/bin
```

Установка на подключённое root-устройство:

```bash
./scripts/deploy-kmod.sh android14-6.1
```

Сокрытие файлов интерфейсов VPN выполняется демоном через SUSFS
`add_sus_path_loop`, чтобы правило повторно применялось к новым пользовательским
процессам и динамическим путям интерфейса. После удаления и повторного создания интерфейса пути
регистрируются заново. Если SUSFS или его команда недоступны, демон не
завершается, а пишет ограниченное по частоте сообщение в `daemon.log`.

### Применение kpatch

`kpatch` встраивает драйвер в дерево `kernel/common` и не создаёт `.ko`. Точки вызова для всех поддерживаемых профилей, включая legacy 4.9/4.14/4.19/5.4, вставляются структурными Python-скриптами. Исходное дерево должно быть чистым:

```bash
./kpatch/scripts/apply.sh /path/to/kernel/common android14-6.1
```

В конфигурации ядра нужно включить `CONFIG_VPNHIDE=y`, затем собрать ядро штатным GKI/Kleaf-способом. Для проверки в QEMU:

```bash
./kpatch/test/build-kernel.sh android14-6.1
./kpatch/test/run.sh android14-6.1
```

Профиль `upstream-4.9` закреплён за Linux `v4.9.337` и предназначен для
Android-ядер, в которых соответствующая сетевая часть близка к upstream 4.9.
Это не универсальный OEM-профиль: при отличающейся
структуре исходников инжектор завершится с ошибкой, а не применит нечёткий
патч.

Воспроизводимая QEMU-проверка legacy-профиля:

```bash
./kpatch/test/build-kernel.sh upstream-4.9
./kpatch/test/run.sh upstream-4.9
```

В Linux до 4.16 нет ABI именованных BPF map, необходимого для вектора BPF
laundering, и API UDP GSO (`UDP_SEGMENT`). Для этого профиля эти два вектора
выводятся как `SKIP`; все поддерживаемые ядром векторы остаются обязательными
для прохождения.
