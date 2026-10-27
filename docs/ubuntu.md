# Ubuntu / Debian setup

Step-by-step install for `apt`-based distros, where neither this stack nor
`open-fprintd` is packaged. Verified on **Ubuntu 26.04 (kernel 7.0)** with a
**Huawei MateBook FLMH-XX** (ACPI `SIL6250`).

The two Arch-tested paths in the [README](../README.md) (`makepkg` and
`install.sh`) assume `open-fprintd` is already present. On `apt` distros you
install `open-fprintd` from source first, and that needs one step the upstream
README omits on systemd distros — see [open-fprintd](#open-fprintd) below.

## 1. Build dependencies

```sh
sudo apt install build-essential dkms linux-headers-$(uname -r) \
                 libssl-dev pkg-config git
```

`dkms` is optional but recommended: `install.sh` uses it automatically so the
kernel module is rebuilt on every kernel upgrade. Without it the module is
installed out-of-tree and **stops working after the next kernel update** until
you re-run `./install.sh kernel`.

The distro Rust may be older than this project's pinned `Cargo.lock` needs; use
[rustup](https://rustup.rs) for a current stable toolchain:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup default stable
```

## 2. open-fprintd

`sil6250d` is a backend for [open-fprintd](https://github.com/uunicorn/open-fprintd);
without it `fprintd-enroll` finds no device. Install it from source:

```sh
git clone https://github.com/uunicorn/open-fprintd
cd open-fprintd
sudo python3 setup.py install --force --install-layout deb --prefix=/usr --root=/

# REQUIRED on systemd distros, and NOT done by setup.py:
sudo install -Dm644 debian/open-fprintd.service /etc/systemd/system/open-fprintd.service
sudo systemctl daemon-reload
```

Why the extra step: `open-fprintd` ships a D-Bus activation file that hands the
`net.reactivated.Fprint` name to systemd via
`SystemdService=open-fprintd.service`. `setup.py install` installs the
activation file but not that unit, so on a systemd system the activation fails
and `fprintd-enroll` reports no device. The `.deb` in `open-fprintd/debian/`
ships the unit; the source install does not, hence the manual copy above.

Notes:

- `open-fprintd` takes over only the fingerprint **daemon** role. The distro
  `fprintd` package stays installed and still provides the `fprintd-enroll` /
  `fprintd-verify` CLIs and `pam_fprintd`. A source install (unlike the
  `open-fprintd` `.deb`, which `Conflicts: fprintd`) leaves that package in
  place.
- `setup.py install` overwrites the distro's
  `/usr/share/dbus-1/system-services/net.reactivated.Fprint.service`. Back it up
  first if you want a clean revert:
  `sudo cp /usr/share/dbus-1/system-services/net.reactivated.Fprint.service{,.fprintd.orig}`.

## 3. Build + install this stack

```sh
git clone https://github.com/AlexDaichendt/sil6250-linux.git
cd sil6250-linux
./install.sh            # kernel module (via DKMS) + sil6250d daemon
```

`install.sh` uses `sudo` for the system-level steps and builds the daemon as
your normal user. See [`install.sh`](../install.sh) for exactly what it copies
where.

## 4. Enrol and verify

```sh
fprintd-enroll          # touch the power-button sensor until it completes
fprintd-verify          # should report verify-match
```

## 5. PAM (login and sudo by finger)

```sh
sudo pam-auth-update --enable fprintd
```

The `fprintd` PAM profile is `sufficient` and sits above the password module,
so a fingerprint match logs you in while the password stays as a fallback — do
not remove password auth. Disable again with
`sudo pam-auth-update --disable fprintd`.

## Troubleshooting

- **Module bound?** `dmesg | grep sil6250` should show
  `ready: window 0x...fe800000/... irq=... -> /dev/sil6250`, and `/dev/sil6250`
  should exist. If not, confirm the ACPI device is present:
  `ls -d /sys/bus/acpi/devices/SIL6250:*`.
- **Services:** `systemctl status open-fprintd sil6250d`. `sil6250d` should be
  `active`; `open-fprintd` is D-Bus activated (started on first
  `fprintd-*` call).
- **Transport/TLS smoke test** (no finger, no daemon needed):

  ```sh
  systemctl stop sil6250d
  cargo build -p sil6250 --example hsdiag
  sudo target/debug/examples/hsdiag /dev/sil6250 provision
  ```

  Look for `RESULT: PASS ... identity=match`, then
  `systemctl start sil6250d`.
- **Fingerprint stopped working after a kernel upgrade:** the module was not on
  DKMS. Install `dkms` (step 1) and re-run `./install.sh kernel`.
- **Secure Boot on:** DKMS must sign the module with an enrolled MOK key, or
  `modprobe` rejects it — `install.sh` prints the `mokutil --import` command to
  run before rebooting.
