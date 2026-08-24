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

Supported variants are: `android12-5.4`, `android12-5.10`, `android13-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`, and `android16-6.12`.

The in-tree kpatch compatibility profiles additionally cover Android common 5.4 and upstream 4.19.325 (`kpatch/versions/android12-5.4`, `kpatch/versions/upstream-4.19`). Legacy checks are intentionally bounded to one compiler job; use `VPNHIDE_BUILD_JOBS=1` and run one KMI at a time on WSL2.

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

Архив `vpnhide-kmod-<kmi>.zip` появится в корне репозитория. Поддерживаются KMI: `android12-5.10`, `android13-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`.

Для локальной сборки с уже установленными исходниками ядра и LLVM:

```bash
./kmod/build.py --kmi android14-6.1 \
  --kdir /path/to/kernel --clang-dir /path/to/clang/bin
```

Установка на подключённое root-устройство:

```bash
./scripts/deploy-kmod.sh android14-6.1
```

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
