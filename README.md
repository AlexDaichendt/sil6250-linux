# SIL6250 fingerprint driver for Linux

A complete Linux stack for the **Silead SIL6250 / Petaic** match-on-host
fingerprint sensor (as found in the Huawei MateBook X Pro 2024), so it works
with the normal desktop fingerprint experience: enrol in GNOME/KDE Settings, log
in and `sudo` with your finger via PAM.

The sensor is unusual: it is a 64×80 touch reader reached over an
**EC-arbitrated shared-memory mailbox**, not USB or SPI, behind a TLS-PSK secure
channel. There is no public driver. This repo is a clean, self-contained
reimplementation built from reverse engineering.

> This repo was created with assistance from various LLMs. If you prefer your 
> code to be written only by humans, please move on.

## Quick start

Install [open-fprintd](https://github.com/uunicorn/open-fprintd) first (your
distro may package it).

```bash
# Install it from the AUR
paru -S open-fprintd
# You are not on Arch; probably have to build it from source.
git clone https://github.com/uunicorn/open-fprintd
cd open-fprintd
./setup.py install --force --install-layout deb --prefix=/usr --root=/
```

### Arch Linux (recommended): `makepkg`

The stack is packaged as two `PKGBUILD`s under
[`packaging/aur/`](packaging/aur/): `sil6250-dkms` (kernel module + udev rule,
via DKMS) and `sil6250d` (the daemon, systemd unit, D-Bus policy). They are not
on the AUR yet, so build them from this checkout. Build the DKMS package first —
`sil6250d` depends on it:

```sh
git clone https://github.com/AlexDaichendt/sil6250-linux.git
cd sil6250-linux

(cd packaging/aur/sil6250-dkms && makepkg -si)   # kernel module + udev rule
(cd packaging/aur/sil6250d    && makepkg -si)    # daemon (pulls in open-fprintd)

# The sil6250d package loads the module and enables+starts the service for you.
# enroll a finger via CLI (or any GUI program — they all use fprintd underneath)
fprintd-enroll
```

`makepkg -si` builds the package and installs it with `pacman`, so everything is
tracked and uninstallable with `pacman -R sil6250d sil6250-dkms`. These are VCS
(`-git`) packages that build from the current `main`. See
[`packaging/aur/README.md`](packaging/aur/README.md) for details.

### Other distros: `install.sh`

Use an up-to-date stable Rust toolchain to build the daemon. The compiler
packaged by your distribution may be too old for the locked dependencies;
[rustup](https://rust-lang.org/tools/install/) is the recommended way to obtain
a current toolchain. Run Cargo as your regular user; `install.sh` requests
root privileges for system installation steps.

```sh
git clone https://github.com/AlexDaichendt/sil6250-linux.git
cd sil6250-linux
```

If using rustup, select the stable toolchain for this checkout:

```sh
rustup toolchain install stable
rustup override set stable
```

Build and install using the committed dependency versions in `Cargo.lock`:

```sh
# build + install everything (kernel module, sil6250d daemon)
# Tested on CachyOS and Omarchy - in case it fails, you can easily install the components by hand.
# Check the install.sh script what it is copying where.
./install.sh

fprintd-enroll
```

`install.sh` runs two stages — `kernel`, `daemon` — and you can run any subset,
e.g. `./install.sh kernel`. It uses `sudo` only for steps that install
system-wide. Override the install prefix with `PREFIX=/usr`.


## Architecture

```
  GNOME/KDE Settings, PAM (sudo/login)
            │  D-Bus
          open-fprintd
            │  io.github.uunicorn.Fprint.Device
          sil6250d  (this repo, sil6250d/)   ← standalone Rust daemon
            │ uses
      ┌─────┴────────────────────────────────────┐
      │  sil6250  (this repo, sil6250/)           │
      │  • mailbox framing       (proto.rs)       │
      │  • TLS-PSK + capture     (engine.rs)      │
      │  • host matcher          (matcher/sift.rs)│
      └─────┬────────────────────────────────────┘
            │ /dev/sil6250  (mmap + ioctl)
      sil6250.ko  (this repo, kernel/)   ← resource broker (C)
            │ ACPI platform device "SIL6250"
    hardware   EC mailbox window + GPIO strobes + IRQ
```

Each layer is as thin as possible:

- **`kernel/` — `sil6250.ko`**: a minimal C ACPI platform driver with *no
  protocol logic*. It ioremaps the mailbox window and exposes it as
  `/dev/sil6250` (`mmap` the window, `ioctl` for the GPIO strobes + IRQ wait).
- **`sil6250/` — Rust library crate**: where all the real work lives — mailbox
  framing, the TLS-PSK secure channel, the `0x11 → 0x37 → 0x38` capture loop,
  and the host-side matcher (the sensor only streams raw images; the 3.2×4 mm
  patch is too small for the NBIS minutiae pipeline). Independently usable as a
  library; the matcher is a patent-free clean-room reimplementation.
- **`sil6250d/` — Rust daemon**: implements the
  `io.github.uunicorn.Fprint.Device` D-Bus interface and registers with
  [open-fprintd](https://github.com/uunicorn/open-fprintd). Enrol/verify/identify
  run as async D-Bus calls; the blocking sil6250 work runs on a thread pool.
  Enrolled prints are stored in `/var/lib/open-fprintd/sil6250/`.

## How it was built

The sensor is undocumented and has no public driver; this stack was produced by
reverse engineering. The full story — hardware identification, the EC mailbox
transport, the TLS-PSK channel, and the clean-room reimplementation of the
match-on-host algorithm — is in **`REVERSE_ENGINEERING_DETAILS.md`**.

## Credits

- [**Void755/gxfp_linux_driver**](https://github.com/Void755/gxfp_linux_driver)
  — the open-source GXFP5130 driver for the Goodix sibling sensor on the same
  `\_SB.SPBA` ACPI node and `0xFE800000` mailbox window. Its working, ACK-getting
  kernel code was the verified reference for the EC mailbox transport (the TX/RX
  window split, the GPIO handshake strobes, and the EC arbitration model). See
  `REVERSE_ENGINEERING_DETAILS.md` §3.2.
- [**uunicorn/open-fprintd**](https://github.com/uunicorn/open-fprintd) — the
  fprintd-compatible daemon that accepts out-of-tree device backends over D-Bus,
  making a standalone driver possible without patching libfprint.

## License

LGPL-2.1 (see `LICENSE`).
