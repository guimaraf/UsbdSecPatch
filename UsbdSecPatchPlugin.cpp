/*
    UsbdSecPatchPlugin.cpp

    Xbox 360 kernel patch to allow custom USB peripherals.

    Original author: InvoxiPlayGames
    Enhanced by: Community contribution

    Features:
    - Patches UsbdIsDeviceAuthenticated to always return true
    - Patches WgcAddDevice to skip interface check (kernel 17559)
    - NEW: Tracks devices by USB topology to support multiple identical
   controllers

    License: WTFPL
*/

#include "ppcasm.h"
#include <xtl.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

// Maximum number of identical devices to track
#define MAX_TRACKED_DEVICES 8

// Enable debug output via DbgPrint
#define DEBUG_OUTPUT 1

// ============================================================================
// KERNEL VERSION INFO
// ============================================================================

// Patch address for 17559 - the bne after UsbdGetEndpointDescriptor in
// WgcAddDevice
#define WGCADDDEVICE_INST_17559 0x800F98E0

// Add more kernel versions as needed
// #define WGCADDDEVICE_INST_17526 0x????????

// ============================================================================
// KERNEL STRUCTURES
// ============================================================================

typedef struct _XBOX_KRNL_VERSION {
  WORD Major;
  WORD Minor;
  WORD Build;
  WORD Qfe;
} XBOX_KRNL_VERSION, *PXBOX_KRNL_VERSION;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;           // 0x0 sz:0x8
  LIST_ENTRY InClosureOrderLinks;        // 0x8 sz:0x8
  LIST_ENTRY InInitializationOrderLinks; // 0x10 sz:0x8
  PVOID NtHeadersBase;                   // 0x18 sz:0x4
  PVOID ImageBase;                       // 0x1C sz:0x4
  DWORD SizeOfNtImage;                   // 0x20 sz:0x4
  UNICODE_STRING FullDllName;            // 0x24 sz:0x8
  UNICODE_STRING BaseDllName;            // 0x2C sz:0x8
  DWORD Flags;                           // 0x34 sz:0x4
  DWORD SizeOfFullImage;                 // 0x38 sz:0x4
  PVOID EntryPoint;                      // 0x3C sz:0x4
  WORD LoadCount;                        // 0x40 sz:0x2
  WORD ModuleIndex;                      // 0x42 sz:0x2
  PVOID DllBaseOriginal;                 // 0x44 sz:0x4
  DWORD CheckSum;                        // 0x48 sz:0x4
  DWORD ModuleLoadFlags;                 // 0x4C sz:0x4
  DWORD TimeDateStamp;                   // 0x50 sz:0x4
  PVOID LoadedImports;                   // 0x54 sz:0x4
  PVOID XexHeaderBase;                   // 0x58 sz:0x4
  union {
    STRING LoadFileName; // 0x5C sz:0x8
    struct {
      PVOID ClosureRoot;     // 0x5C sz:0x4 LDR_DATA_TABLE_ENTRY
      PVOID TraversalParent; // 0x60 sz:0x4 LDR_DATA_TABLE_ENTRY
    } asEntry;
  } inf;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; // size 100

// ============================================================================
// USB TOPOLOGY STRUCTURE (for tracking identical devices)
// ============================================================================

// USB Topology information - identifies physical port location
typedef struct _USB_TOPOLOGY_INFO {
  BYTE RootHubPort; // Root hub port number (1-4)
  BYTE HubPort;     // Hub port number if connected through hub (0 if direct)
  BYTE HubDepth;    // Depth in hub chain (0 = direct to root hub)
  BYTE Reserved;    // Padding/alignment
} USB_TOPOLOGY_INFO, *PUSB_TOPOLOGY_INFO;

// Tracked device entry
typedef struct _TRACKED_DEVICE {
  BOOL InUse;                 // Is this slot in use?
  PVOID DeviceHandle;         // Device handle from kernel
  USB_TOPOLOGY_INFO Topology; // Physical location
  WORD VendorId;              // USB VID
  WORD ProductId;             // USB PID
  DWORD LastSeenTime;         // Timestamp for cleanup
} TRACKED_DEVICE, *PTRACKED_DEVICE;

// Global device tracking table
static TRACKED_DEVICE g_TrackedDevices[MAX_TRACKED_DEVICES] = {0};
static DWORD g_TrackedDeviceCount = 0;

// ============================================================================
// KERNEL IMPORTS
// ============================================================================

EXTERN_C {
  // Standard debug output
  VOID DbgPrint(const char *s, ...);

  // Module handling
  DWORD XexGetModuleHandle(PCSTR moduleName, PHANDLE hand);
  DWORD XexGetProcedureAddress(HANDLE hand, DWORD dwOrdinal, PVOID Address);

  // Kernel version
  extern PXBOX_KRNL_VERSION XboxKrnlVersion;
}

// ============================================================================
// KERNEL USB FUNCTION ORDINALS
// ============================================================================

// These ordinals were found via Xenia emulator source code analysis
#define ORDINAL_UsbdAddDeviceComplete 0x2E4         // 740
#define ORDINAL_UsbdCancelAsyncTransfer 0x2E5       // 741
#define ORDINAL_UsbdGetDeviceSpeed 0x2E6            // 742
#define ORDINAL_UsbdGetDeviceTopology 0x2E7         // 743 - KEY FUNCTION!
#define ORDINAL_UsbdGetEndpointDescriptor 0x2E8     // 744
#define ORDINAL_UsbdIsDeviceAuthenticated 0x2E9     // 745
#define ORDINAL_UsbdOpenDefaultEndpoint 0x2EA       // 746
#define ORDINAL_UsbdOpenEndpoint 0x2EB              // 747
#define ORDINAL_UsbdQueueAsyncTransfer 0x2EC        // 748
#define ORDINAL_UsbdQueueCloseDefaultEndpoint 0x2ED // 749
#define ORDINAL_UsbdQueueCloseEndpoint 0x2EE        // 750
#define ORDINAL_UsbdRemoveDeviceComplete 0x2EF      // 751
#define ORDINAL_UsbdResetDevice 0x2F6               // 758
#define ORDINAL_UsbdGetDeviceDescriptor 0x2F7       // 759
#define ORDINAL_XInputdGetDevicePid 0x316           // 790

// ============================================================================
// FUNCTION POINTER TYPES
// ============================================================================

// UsbdGetDeviceTopology - Gets physical USB port location
// Parameters are estimates based on similar Windows USB APIs
typedef DWORD (*PFN_UsbdGetDeviceTopology)(
    PVOID DeviceHandle,             // Device handle
    PUSB_TOPOLOGY_INFO TopologyInfo // Output: topology information
);

// UsbdGetDeviceDescriptor - Gets USB device descriptor
typedef DWORD (*PFN_UsbdGetDeviceDescriptor)(
    PVOID DeviceHandle,     // Device handle
    PVOID DescriptorBuffer, // Output buffer
    DWORD BufferLength      // Buffer size
);

// Global function pointers (resolved at runtime)
static PFN_UsbdGetDeviceTopology g_pfnUsbdGetDeviceTopology = NULL;
static PFN_UsbdGetDeviceDescriptor g_pfnUsbdGetDeviceDescriptor = NULL;

// ============================================================================
// DEVICE TRACKING FUNCTIONS
// ============================================================================

#if DEBUG_OUTPUT
#define DBG_PRINT(fmt, ...) DbgPrint("UsbdSecPatch | " fmt "\n", ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

// Find a tracked device by its topology (physical location)
static PTRACKED_DEVICE FindDeviceByTopology(PUSB_TOPOLOGY_INFO Topology) {
  for (int i = 0; i < MAX_TRACKED_DEVICES; i++) {
    if (g_TrackedDevices[i].InUse) {
      if (g_TrackedDevices[i].Topology.RootHubPort == Topology->RootHubPort &&
          g_TrackedDevices[i].Topology.HubPort == Topology->HubPort &&
          g_TrackedDevices[i].Topology.HubDepth == Topology->HubDepth) {
        return &g_TrackedDevices[i];
      }
    }
  }
  return NULL;
}

// Find a tracked device by its handle
static PTRACKED_DEVICE FindDeviceByHandle(PVOID DeviceHandle) {
  for (int i = 0; i < MAX_TRACKED_DEVICES; i++) {
    if (g_TrackedDevices[i].InUse &&
        g_TrackedDevices[i].DeviceHandle == DeviceHandle) {
      return &g_TrackedDevices[i];
    }
  }
  return NULL;
}

// Add a new device to tracking table
static PTRACKED_DEVICE AddTrackedDevice(PVOID DeviceHandle,
                                        PUSB_TOPOLOGY_INFO Topology) {
  // First check if device at this topology already exists
  PTRACKED_DEVICE existing = FindDeviceByTopology(Topology);
  if (existing) {
    // Update existing entry with new handle
    existing->DeviceHandle = DeviceHandle;
    DBG_PRINT("Updated device at topology [%d:%d:%d] with new handle %p",
              Topology->RootHubPort, Topology->HubPort, Topology->HubDepth,
              DeviceHandle);
    return existing;
  }

  // Find empty slot
  for (int i = 0; i < MAX_TRACKED_DEVICES; i++) {
    if (!g_TrackedDevices[i].InUse) {
      g_TrackedDevices[i].InUse = TRUE;
      g_TrackedDevices[i].DeviceHandle = DeviceHandle;
      g_TrackedDevices[i].Topology = *Topology;
      g_TrackedDevices[i].VendorId = 0; // Will be filled later
      g_TrackedDevices[i].ProductId = 0;
      g_TrackedDeviceCount++;

      DBG_PRINT("Added device at topology [%d:%d:%d] handle %p (total: %d)",
                Topology->RootHubPort, Topology->HubPort, Topology->HubDepth,
                DeviceHandle, g_TrackedDeviceCount);
      return &g_TrackedDevices[i];
    }
  }

  DBG_PRINT("ERROR: Device tracking table full! Max %d devices",
            MAX_TRACKED_DEVICES);
  return NULL;
}

// Remove a device from tracking table
static BOOL RemoveTrackedDevice(PVOID DeviceHandle) {
  PTRACKED_DEVICE device = FindDeviceByHandle(DeviceHandle);
  if (device) {
    DBG_PRINT("Removed device at topology [%d:%d:%d] handle %p",
              device->Topology.RootHubPort, device->Topology.HubPort,
              device->Topology.HubDepth, DeviceHandle);

    device->InUse = FALSE;
    device->DeviceHandle = NULL;
    g_TrackedDeviceCount--;
    return TRUE;
  }
  return FALSE;
}

// ============================================================================
// PATCH APPLICATION
// ============================================================================

static BOOL ApplyAuthenticationPatch(HANDLE hKernel) {
  PDWORD pdwUsbdAuthFunction = NULL;

  // Find UsbdIsDeviceAuthenticated's export (ordinal 745 = 0x2E9)
  XexGetProcedureAddress(hKernel, ORDINAL_UsbdIsDeviceAuthenticated,
                         &pdwUsbdAuthFunction);
  DBG_PRINT("Got UsbdIsDeviceAuthenticated at %p", pdwUsbdAuthFunction);

  if (pdwUsbdAuthFunction == NULL) {
    DBG_PRINT("ERROR: Could not find UsbdIsDeviceAuthenticated!");
    return FALSE;
  }

  // Patch the function to always return true
  // li r3, 1  - Load immediate value 1 into register 3 (return value)
  // blr       - Branch to link register (return)
  pdwUsbdAuthFunction[0] = LI(3, 1);
  pdwUsbdAuthFunction[1] = BLR;

  DBG_PRINT("Patched UsbdIsDeviceAuthenticated to return TRUE");
  return TRUE;
}

static BOOL ApplyWgcAddDevicePatch(void) {
  DWORD patchAddress = 0;

  // Select patch address based on kernel version
  switch (XboxKrnlVersion->Build) {
  case 17559:
    patchAddress = WGCADDDEVICE_INST_17559;
    break;
  // Add more versions here as they are discovered
  // case 17526:
  //     patchAddress = WGCADDDEVICE_INST_17526;
  //     break;
  default:
    DBG_PRINT("WgcAddDevice patch not available for kernel %d",
              XboxKrnlVersion->Build);
    return FALSE;
  }

  // Replace bne cr6, 0x10 with b 0x10
  // This skips the NULL check after UsbdGetEndpointDescriptor(device, 0, 3, 1)
  POKE_B(patchAddress, patchAddress + 0x10);

  DBG_PRINT("Patched WgcAddDevice at 0x%08X for kernel %d", patchAddress,
            XboxKrnlVersion->Build);
  return TRUE;
}

static BOOL InitializeTopologyTracking(HANDLE hKernel) {
  // Try to resolve UsbdGetDeviceTopology
  XexGetProcedureAddress(hKernel, ORDINAL_UsbdGetDeviceTopology,
                         &g_pfnUsbdGetDeviceTopology);

  if (g_pfnUsbdGetDeviceTopology == NULL) {
    DBG_PRINT("WARNING: UsbdGetDeviceTopology not found - multiple identical "
              "devices may conflict");
    return FALSE;
  }

  DBG_PRINT("Got UsbdGetDeviceTopology at %p", g_pfnUsbdGetDeviceTopology);

  // Also try to get UsbdGetDeviceDescriptor for VID/PID info
  XexGetProcedureAddress(hKernel, ORDINAL_UsbdGetDeviceDescriptor,
                         &g_pfnUsbdGetDeviceDescriptor);
  if (g_pfnUsbdGetDeviceDescriptor) {
    DBG_PRINT("Got UsbdGetDeviceDescriptor at %p",
              g_pfnUsbdGetDeviceDescriptor);
  }

  // Initialize tracking table
  for (int i = 0; i < MAX_TRACKED_DEVICES; i++) {
    g_TrackedDevices[i].InUse = FALSE;
  }
  g_TrackedDeviceCount = 0;

  DBG_PRINT("Device topology tracking initialized (max %d devices)",
            MAX_TRACKED_DEVICES);
  return TRUE;
}

// ============================================================================
// EXPORTED HELPER FUNCTIONS
// For use by other plugins or for debugging
// ============================================================================

// Get the topology of a connected device
EXTERN_C DWORD UsbdSecPatch_GetDeviceTopology(PVOID DeviceHandle,
                                              PUSB_TOPOLOGY_INFO OutTopology) {
  if (!g_pfnUsbdGetDeviceTopology || !DeviceHandle || !OutTopology) {
    return (DWORD)-1;
  }
  return g_pfnUsbdGetDeviceTopology(DeviceHandle, OutTopology);
}

// Check if a device is being tracked
EXTERN_C BOOL UsbdSecPatch_IsDeviceTracked(PVOID DeviceHandle) {
  return FindDeviceByHandle(DeviceHandle) != NULL;
}

// Get count of tracked devices
EXTERN_C DWORD UsbdSecPatch_GetTrackedDeviceCount(void) {
  return g_TrackedDeviceCount;
}

// ============================================================================
// DLL ENTRY POINT
// ============================================================================

BOOL APIENTRY DllMain(HANDLE hInstDLL, DWORD dwReason, LPVOID lpReserved) {
  HANDLE hKernel = NULL;

  if (dwReason == DLL_PROCESS_ATTACH) {
    DBG_PRINT("===========================================");
    DBG_PRINT("UsbdSecPatch v2.0 - Enhanced Edition");
    DBG_PRINT("Kernel version: %d.%d.%d.%d", XboxKrnlVersion->Major,
              XboxKrnlVersion->Minor, XboxKrnlVersion->Build,
              XboxKrnlVersion->Qfe);
    DBG_PRINT("===========================================");

    // Get kernel module handle
    XexGetModuleHandle("xboxkrnl.exe", &hKernel);
    if (hKernel == NULL) {
      DBG_PRINT("FATAL: Could not get kernel handle!");
      goto end;
    }

    // Apply the authentication bypass patch
    if (!ApplyAuthenticationPatch(hKernel)) {
      DBG_PRINT("WARNING: Authentication patch failed!");
    }

    // Apply WgcAddDevice patch (version-specific)
    if (!ApplyWgcAddDevicePatch()) {
      DBG_PRINT(
          "INFO: WgcAddDevice patch skipped (unsupported kernel version)");
    }

    // Initialize topology-based device tracking
    if (!InitializeTopologyTracking(hKernel)) {
      DBG_PRINT("INFO: Topology tracking disabled");
    }

    DBG_PRINT("Initialization complete!");
    DBG_PRINT(
        "NOTE: Re-plug controllers after power-on for changes to take effect");

  end:
    // Set load count to 1 to keep plugin loaded
    ((LDR_DATA_TABLE_ENTRY *)hInstDLL)->LoadCount = 1;
    return FALSE; // Return FALSE to prevent DllMain being called again
  }

  return TRUE;
}
