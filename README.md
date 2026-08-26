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

Supported variants are: `android12-5.10`, `android13-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`, and `android17-6.18`.

To clone Google `kernel/common`, apply the matching kpatch profile, build the GKI kernel metadata, and package a fresh 6.18 kmod in one step:

```bash
./scripts/build-gki-kmod.sh
```

The script accepts an optional KMI and job count, for example
`./scripts/build-gki-kmod.sh android17-6.18 16`. It uses a disposable `/tmp`
build tree; set `VPNHIDE_KEEP_BUILD=1` to keep it for debugging.

The in-tree kpatch compatibility profiles additionally cover Android common 5.4 and upstream 4.19.325 (`kpatch/versions/android12-5.4`, `kpatch/versions/upstream-4.19`). Local QEMU matrices always run one build/container at a time. Test containers default to 32 compiler jobs with an 11 GiB hard memory limit; override these with `VPNHIDE_BUILD_JOBS` and `VPNHIDE_BUILD_MEMORY` for smaller hosts.

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

## Applying kpatch

`kpatch` does not produce a `.ko` file. It copies the driver into `security/vpnhide`, copies the public header into `include/linux`, and applies the version-specific patches to a `kernel/common` tree. VPNHide must then be built into the kernel with `CONFIG_VPNHIDE=y`.

The source tree must be clean before applying the patches:

```bash
./kpatch/scripts/apply.sh \
  /path/to/kernel/common \
  android14-6.1
```

Enable the following kernel configuration and build the kernel using the normal GKI/Kleaf workflow for that tree:

```text
CONFIG_VPNHIDE=y
```

The second argument to `apply.sh` selects the patch set. The supported versions are the same as those listed above.

For a quick QEMU build and runtime check:

```bash
./kpatch/test/build-kernel.sh android14-6.1
./kpatch/test/run.sh android14-6.1
```

To run the complete matrix sequentially, including clean builds for the
legacy 4.19 and 5.4 profiles:

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

Полная сборка kmod GKI 6.18 прямо из Google kernel/common:

```bash
./scripts/build-gki-kmod.sh
```

Скрипт сам клонирует исходники, применяет патчи, собирает kernel metadata и
создаёт `vpnhide-kmod-android17-6.18.zip`. Для отладки можно сохранить дерево
сборки: `VPNHIDE_KEEP_BUILD=1 ./scripts/build-gki-kmod.sh`.

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

`kpatch` встраивает драйвер в дерево `kernel/common` и не создаёт `.ko`. Исходное дерево должно быть чистым:

```bash
./kpatch/scripts/apply.sh /path/to/kernel/common android14-6.1
```

В конфигурации ядра нужно включить `CONFIG_VPNHIDE=y`, затем собрать ядро штатным GKI/Kleaf-способом. Для проверки в QEMU:

```bash
./kpatch/test/build-kernel.sh android14-6.1
./kpatch/test/run.sh android14-6.1
```
