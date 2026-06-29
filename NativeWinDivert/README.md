# windivert_game_filter

Native DLL used by `BannerlordFirewall.dll`.

Exports:

- `SetProtectedUdpPort(uint16_t port)`
- `SetBlockedIPLogCallback(callback)`
- `StartFilter()`
- `StopFilter()`
- `AddAllowedIP(uint32_t ip)`
- `RemoveAllowedIP(uint32_t ip)`

The filter intercepts inbound IPv4 UDP packets. Packets targeting the configured UDP port are reinjected only when the source IP is in the allowed list. Other inbound UDP packets pass through unchanged. Blocked packets are reported through the callback immediately; the C# mod aggregates them into one global log/webhook message every 10 seconds.

## Build

Install/extract the WinDivert binary package and install Visual Studio C++ Build Tools. Then run:

```bat
set WINDIVERT_DIR=C:\WinDivert-2.2.2-A
cd NativeWinDivert
build.bat
```

`build.bat` copies these files next to `BannerlordFirewall.dll` automatically:

- `windivert_game_filter.dll`
- `WinDivert.dll`
- `WinDivert64.sys`

For this repo that output folder is usually:

```text
bin\Win64_Shipping_Server\
```

## Standalone RDP 3389 Guard

`rdp_3389_guard.c` builds a separate EXE that continuously protects inbound TCP/3389 with a source-IP allowlist. Unknown source IPs are dropped and logged every 10 seconds with the blocked packet count.

Build:

```bat
set WINDIVERT_DIR=C:\WinDivert-2.2.2-A
cd NativeWinDivert
build_rdp_guard.bat
```

Run as Administrator:

```bat
rdp_3389_guard.exe --allow YOUR.PUBLIC.IP
```

Or with a file:

```bat
rdp_3389_guard.exe --allow-file rdp_allowed_ips.txt
```

The EXE refuses to start with an empty allowlist to avoid locking you out of RDP.
