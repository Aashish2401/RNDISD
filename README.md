# Android USB tethering for your Mac

Plug in an iPhone and your Mac just shares its connection over the cable. Plug
in an Android phone and, until now, nothing happens. Macs have no driver for
RNDIS, the protocol Android (notably Samsung) uses for USB tethering, and the
old HoRNDIS kernel extension is abandoned and doesn't work on Apple Silicon.

**rndisd fixes that.** It's a small userspace daemon that talks RNDIS to your
phone over libusb, so you get wired Android tethering on a modern Mac with **no
kernel extension, no lowered system security, and no paid app**. You don't need
an iPhone just to tether over USB. iPhones keep working natively alongside it.

> **Status: experimental.** Tested on one setup: Samsung Galaxy S24 Ultra
> (One UI 9) and an M4 MacBook Air. Verified: RNDIS handshake, DHCP lease,
> ping to the phone's gateway (~1.5 ms, no loss), and internet access over the
> cable (`curl --interface feth40 https://example.com` returns 200).
> **Not yet automatic:** macOS keeps Wi-Fi as the default route, so see
> "Routing" below. Please report what works on your hardware.

## How it works

1. Polls USB for devices exposing an RNDIS interface pair (class `E0/01/03`,
   `02/02/FF`, or `EF/04/01`) plus a CDC data interface.
2. Claims them with libusb and performs the RNDIS handshake.
3. Creates a `feth` pair (default `feth40`/`feth41`) and moves Ethernet frames
   between the phone and the pair via `/dev/bpf`.
4. Runs DHCP on `feth40` with `ipconfig`, so macOS gets an address and gateway.

It ignores everything else: Apple devices (vendor `0x05AC`), phones already in
NCM/ECM mode, keyboards, and so on. **iPhone USB tethering keeps using macOS's
built-in support**, and the two coexist.

## Requirements

- Apple Silicon or Intel Mac, a recent macOS
- Homebrew, plus `brew install libusb pkg-config`
- An Android phone with **USB tethering** turned on, and a data-capable cable

## Install

```sh
git clone https://github.com/YOUR_USER/rndisd.git
cd rndisd
make                 # build as your normal user (needs Homebrew in PATH)
sudo ./rndisd -v     # foreground test: plug in phone, enable USB tethering
```

You should see `RNDIS up`, the phone's MAC, then `DHCP started`. Check:

```sh
ifconfig feth40                      # status: active, with an inet address
ping -c 3 $(ipconfig getoption feth40 router)
route -n get default | grep interface
```

If that works, install it as a boot-time service:

```sh
sudo make install
tail -f /var/log/rndisd.log
```

Remove it with `sudo make uninstall`.

## Routing

`feth40` is not a registered macOS network service, so macOS keeps preferring
Wi-Fi/Ethernet for the default route. To use the phone connection:

- Turn Wi-Fi off, then check `route -n get default | grep interface`, or
- Send a single command over the phone: `curl --interface feth40 https://example.com`

Making `feth40` win the default route automatically is a known TODO (PRs welcome).

## Troubleshooting

- **`launchctl bootstrap` says `Input/output error`**: the files carry a
  download quarantine attribute. Run `xattr -cr .` in the repo folder, then
  `sudo make install` again (the Makefile also clears it on install).
- **Link is up but traffic still uses Wi-Fi**: `feth40` isn't a registered
  macOS network service, so Wi-Fi may keep the default route. Turn Wi-Fi off to
  test, or check `route -n get default`.
- **`claim ... ACCESS` in the log**: something already owns the RNDIS
  interface. Open an issue with the output of `ioreg -p IOUSB -l -w0`.
- **Interface name clash**: run with `-u N` to use `fethN`/`feth(N+1)`.
- **Session drops a few seconds after enabling tethering**: some phones
  re-enumerate USB right after tethering starts. The daemon reconnects by itself.
- **Don't run `./rndisd` while the service is running.** They'd fight over the
  same `feth` pair.
- Verbose logs: `sudo ./rndisd -v`.

## Security notes

- It runs as **root** (BPF, `ifconfig`, `ipconfig`) and parses data from the
  USB device you plug in. Read `rndisd.c` (about 450 lines) before installing it.
- It claims **any** RNDIS device that isn't from Apple, including some LTE
  dongles. Unplug devices you don't want it to touch.

## Limitations

- One device at a time, IPv4 via DHCP only.
- No hotplug callbacks: it polls every 2 seconds.
- Not signed or notarized: you build it yourself.

## License

MIT. See `LICENSE`.
