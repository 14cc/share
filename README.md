# Share

Share gives a jailbroken iPhone or iPad Personal Hotspot without a SIM.

Install it, open Settings › Personal Hotspot, set a password and turn it on. Devices that join get an address and reach each other and the host. Nothing reaches the Internet.

## Compatibility

iOS 12 and up, on iPhone and iPad, rootful or rootless. Wi-Fi-only iPads work too, including iOS 18.

Tested on iOS 12.5.8, 15.8.4, 15.8.5, 15.8.6, 16.3, 16.6.1, 17.6.1 and 17.7.11.

## 5 GHz

Newer iOS picks the band on its own, and Maximize Compatibility in Settings moves the hotspot to 2.4 GHz. iOS 12 keeps the hotspot on 2.4 GHz. On those versions Share uses channels 36 to 48 when your Wi-Fi hardware and region allow them. The change applies after your next reboot.

## Problems

If Share doesn't work on your device, it writes one report to `/var/mobile/Documents/Share-Report.json`. Open it in Filza and send it to me. The report holds no passwords, network names or addresses.

Share also keeps `/var/mobile/Library/Share/status.json` up to date with what it did in `misd` and the last hotspot states. If that file is missing, Share isn't loading into `misd`.

## How it works

Share loads into `misd`, the daemon behind Personal Hotspot. It lifts the cellular requirement and asks for Apple's built-in local network with DHCP. Apple still runs the network, so you keep Apple's name, password and settings. On older iOS, Share also loads into `wifid` to offer 5 GHz channels.

Wi-Fi-only iPads have no carrier to approve the hotspot and no cellular capability, so iOS hides Personal Hotspot. On those iPads Share lets `misd` start without a carrier, and loads into Settings to list Personal Hotspot.

## Build

```sh
SDK=/path/to/iPhoneOS.sdk ./build.sh
```

You need `clang`, `ldid`, `dpkg-deb` and an SDK with arm64e support. The script puts the rootful and rootless packages in `build/` and reads the version from `VERSION`.

```sh
python3 tests/test_support.py
```

To check real daemons too, point `SHARE_FIXTURES` at a folder of `<release>/misd` and `<release>/wifid` files.

## License

GPL-3.0. See `LICENSE`.
