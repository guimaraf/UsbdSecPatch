# UsbdSecPatch - Xbox 360 Custom USB Controller Patch

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](http://www.wtfpl.net/about/)

A kernel patch for Xbox 360 (RGH/JTAG) consoles that enables the use of custom USB controllers and peripherals that don't have official Microsoft authentication chips.

## 📥 Download

Get the latest release (DashLaunch plugin format) from the [Releases page](https://github.com/InvoxiPlayGames/UsbdSecPatch/releases).

---

## Features

### 🎮 Authentication Bypass
Patches `UsbdIsDeviceAuthenticated` to always return `true`, allowing any USB device to be recognized as authenticated. This enables:
- Custom controllers (DIY builds with Arduino, Raspberry Pi Pico, etc.)
- Third-party controllers without authentication chips

### 🔌 Interface Check Skip
Patches `WgcAddDevice` to skip a specific interface descriptor check that fails on certain custom controller firmwares. Currently supported on kernel version **17559**.

### 🆕 Multiple Identical Controllers Support (v2.0)
**New in v2.0**: Added device tracking using USB topology (physical port location) to support multiple identical controllers connected simultaneously.

> **Problem solved**: When two identical controllers (same VID/PID) were connected, only the last one would work because the kernel indexed devices by VID+PID. Now devices are tracked by their physical port position.

---

## Installation

### Method 1: DashLaunch Plugin (Recommended)

1. Copy `UsbdSecPatch.xex` to your Xbox 360 HDD (e.g., `HDD:\Plugins\`)
2. Open DashLaunch settings
3. Add the plugin path under "plugin1", "plugin2", or "plugin3"
4. Reboot your console
5. **Important**: Re-plug your controllers *after* the console boots

### Method 2: NAND Patch (XeBuild)

1. Dump your NAND using J-Runner or similar tool
2. Use the XeBuild patch source (`UsbdSecPatchXeBuild.s`) to apply the patch
3. Build and flash the patched NAND

> ⚠️ **Warning**: The XeBuild patch method has NOT been extensively tested. Use at your own risk.

---

## Compatibility

### Tested Controllers
| Controller | Status | Notes |
|------------|--------|-------|
| Pi Pico "Ardwiino" firmware 8.9.4 | ✅ Working | Guitar Hero XInput mode |
| Gamesir Nova Lite | ✅ Working | Requires v2.0 for multiple units |
| Generic XInput controllers | ✅ Working | - |
| DualShock 4 (via adapter) | ✅ Working | Use Mayflash Magic-NS in XInput mode |
| DualSense (via adapter) | ✅ Working | Use Mayflash Magic-NS in XInput mode |

### Kernel Versions
| Version | Authentication Patch | WgcAddDevice Patch |
|---------|---------------------|-------------------|
| 17559 | ✅ Working | ✅ Working |
| Other | ✅ Working | ❌ Not available (hardcoded address) |

---

## Building from Source

### Prerequisites
- Xbox 360 SDK (XEDK) installed
- `%XEDK%` environment variable configured

### Build Steps

**Plugin version (recommended):**
```batch
build_plugin.bat
```
Output: `UsbdSecPatch.xex`

**XeBuild patch version:**
```batch
build_patch.bat
```
Requires PowerPC GCC toolchain (`%PPC_TOOLCHAIN%` environment variable).

---

## Technical Details

### Kernel Exports Used

| Ordinal | Function | Purpose |
|---------|----------|---------|
| 0x2E7 (743) | `UsbdGetDeviceTopology` | Get physical USB port location |
| 0x2E8 (744) | `UsbdGetEndpointDescriptor` | Get endpoint descriptor |
| 0x2E9 (745) | `UsbdIsDeviceAuthenticated` | **Patched** to return TRUE |
| 0x2F7 (759) | `UsbdGetDeviceDescriptor` | Get USB device descriptor |

### How It Works

1. **Plugin loads** at console startup via DashLaunch
2. **Authentication patch**: Modifies `UsbdIsDeviceAuthenticated` to immediately return `TRUE`
   ```asm
   li r3, 1    ; Load 1 into return register
   blr         ; Return from function
   ```
3. **Interface patch** (kernel 17559): Changes a conditional branch to unconditional in `WgcAddDevice`
   ```asm
   ; Original: bne cr6, 0x10 (branch if not equal)
   ; Patched:  b 0x10        (unconditional branch)
   ```
4. **Device tracking** (v2.0): Maintains internal table of devices indexed by USB topology

### Device Tracking Structure

```c
typedef struct _TRACKED_DEVICE {
    BOOL InUse;                     // Slot in use?
    PVOID DeviceHandle;             // Kernel device handle
    USB_TOPOLOGY_INFO Topology;     // Physical port location
    WORD VendorId;                  // USB VID
    WORD ProductId;                 // USB PID
    DWORD LastSeenTime;             // Cleanup timestamp
} TRACKED_DEVICE;
```

---

## Troubleshooting

### Controller not recognized after boot
- **Solution**: Unplug and re-plug your controller after the console fully boots

### Second identical controller doesn't work  
- **Solution**: Update to v2.0 which includes topology-based tracking
- Make sure both controllers are connected to different USB ports

### WgcAddDevice patch not applied
- Check your kernel version with Aurora or similar dashboard
- The patch currently only supports kernel 17559
- Other kernel versions will still get the authentication bypass

### Debug Output
Enable debug output by setting `DEBUG_OUTPUT 1` in the source code. Debug messages are printed to the kernel debug log (viewable with xbWatson or similar tools).

---

## Contributing

Contributions are welcome! Areas that need work:

1. **Kernel version support**: Finding `WgcAddDevice` patch addresses for other kernel versions
2. **Testing**: Report working/non-working controllers
3. **Documentation**: Improve compatibility tables

---

## Credits

- **InvoxiPlayGames** - Original author
- **Community** - Testing and feedback
- **Xenia Project** - Kernel export ordinal documentation

---

## License

This project is licensed under the [WTFPL](http://www.wtfpl.net/about/) - Do What The F**k You Want To Public License.

---

## Disclaimer

No guarantees are made regarding the stability or effectiveness of this patch. This software modifies your Xbox 360 kernel at runtime. Use at your own risk.

This project is for educational and personal use only on consoles you own. It is not intended to enable piracy or any illegal activities.
