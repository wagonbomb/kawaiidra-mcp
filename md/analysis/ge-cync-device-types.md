# GE Cync - Device Types Catalog

**Target**: com.ge.cbyge v6.20.0
**Analysis Date**: 2026-01-11

---

## Bulbs

### Full Color (RGB + White)

| Device ID | Form Factor | Generation | Notes |
|-----------|-------------|------------|-------|
| `GESingleChipFullColorBulbA19Gen3` | A19 | Gen 3 | Main bulb |
| `GESingleChipFullColorBulbG25Gen1` | G25 Globe | Gen 1 | |
| `GESingleChipFullColorBulbG25Gen2` | G25 Globe | Gen 2 | |
| `GESingleChipFullColorBulbST19Gen1` | ST19 Edison | Gen 1 | |
| `GESingleChipFullColorBulbST19Gen2` | ST19 Edison | Gen 2 | |
| `GEDirectConnectFullColorBulbBR30` | BR30 | Direct | WiFi direct |
| `SingleChipRevealFullColorBulbA19` | A19 | Reveal | Enhanced CRI |
| `SingleChipRevealFullColorBulbA21` | A21 | Reveal | Larger |
| `SingleChipRevealFullColorBulbBR30` | BR30 | Reveal | |

### Tunable White

| Device ID | Form Factor | Notes |
|-----------|-------------|-------|
| `DirectConnectTunableWhiteBulbA19` | A19 | WiFi direct |
| `DirectConnectTunableWhiteBulbBR30` | BR30 | WiFi direct |

### Soft White (Non-Tunable)

| Device ID | Form Factor | Generation |
|-----------|-------------|------------|
| `GESingleChipSoftWhiteBulbG25Gen1` | G25 Globe | Gen 1 |
| `GESingleChipSoftWhiteBulbG25Gen2` | G25 Globe | Gen 2 |
| `GESingleChipSoftWhiteBulbST19Gen1` | ST19 Edison | Gen 1 |
| `GESingleChipSoftWhiteBulbST19Gen2` | ST19 Edison | Gen 2 |

---

## Light Strips

### Indoor

| Device ID | Type | Notes |
|-----------|------|-------|
| `DirectConnectFullColorLightStrip` | Full Color | WiFi direct |
| `GEFullColorStripGen1MadeForGoogle` | Full Color | Google optimized |
| `GEFullColorStripTCOGen2Standalone` | Full Color | Gen 2 standalone |

### Outdoor

| Device ID | Type | Notes |
|-----------|------|-------|
| `OUTDOOR_NEON_STRIP_1` | Neon | Outdoor rated |
| `PrepareToInstallOutdoorLightStrip` | Setup | Provisioning state |

### Segmented

| Device ID | Notes |
|-----------|-------|
| `SegmentedStripTabHostFragment` | UI for segment control |
| `StripMultiColorSchemeItem` | Multi-color schemes |
| `Demo Strip Multicolor Off Scheme` | Demo mode |

---

## Switches

### Paddle Style

| Device ID | Wiring | Generation |
|-----------|--------|------------|
| `GEFourWireSwitchPaddleDimmerGen1` | 4-wire | Gen 1 |
| `GENoNeutralSwitchGen1SwitchPaddle` | No neutral | Gen 1 |

### Toggle Style

| Device ID | Wiring | Generation |
|-----------|--------|------------|
| `GENoNeutralSwitchGen1SwitchToggle` | No neutral | Gen 1 |

### Keypad Style

| Device ID | Wiring | Generation |
|-----------|--------|------------|
| `GEFourWireSwitchKeypadDimmerGen1` | 4-wire | Gen 1 |

### Circle Style

| Device ID | Wiring | Generation |
|-----------|--------|------------|
| `GENoNeutralSwitchGen1SwitchCircle` | No neutral | Gen 1 |

### Configuration Classes

```kotlin
ActionToKeypadSwitchConfiguration
ActionToPaddleSwitchConfiguration
SwitchBrightnessTrimViewModel
```

---

## Dimmers

| Device ID | Type | Notes |
|-----------|------|-------|
| `GEFourWireSwitchKeypadDimmerGen1` | Keypad | Full feature |
| `GEFourWireSwitchPaddleDimmerGen1` | Paddle | Standard |
| `GEDimmingLedsIndicatorBrightness` | LED indicator | Brightness setting |

### Dimmer Settings

```kotlin
Save Switch Load brightness trim
isBrightnessTrimSettingEnabled()
isBrightnessTrimSettingVisible()
brightnessLevel must be in range
```

---

## Plugs

| Device ID | Location | Notes |
|-----------|----------|-------|
| `DISCONNECTING_OUTDOOR_PLUG` | Outdoor | Weather resistant |
| `fun_plug_play_no_local_activator` | Indoor | Easy setup |

---

## Sensors

| Device ID | Type | Notes |
|-----------|------|-------|
| `ThermostatSensorPairingViewModel` | Thermostat | HVAC sensor |
| `ExternalSensorSetDataPoint` | External | Generic sensor |

---

## Cameras (Yi/Kami Integration)

| Component | Purpose |
|-----------|---------|
| `libThingCameraSDK.so` | Camera streaming |
| `libThingP2PSDK.so` | P2P connection |
| `libYiDecrypt.so` | Yi decryption |
| `IPCDeviceSubscribeRequest` | Camera subscription |
| `IPCDeviceAddResponse` | Camera provisioning |

### Camera Features

```kotlin
getDoorBellFaceRecognitionSwitch
setDoorBellFaceRecognitionSwitch
updateAIDetectEventSwitch
switchCamera
switchChannel
```

---

## Hub/Gateway

| Device ID | Purpose |
|-----------|---------|
| `QueryHubDeviceListCommand` | List hub devices |
| `QueryHubFirmwareUpdatesCommand` | Hub OTA |
| `AddAutomationHubCommand` | Hub automation |
| `QUERY_HUB_MESH_NAME_AND_PASSWORD` | Mesh credentials |

---

## Device Categories (Clusters)

### Matter Cluster Support

| Cluster | ID | Devices |
|---------|-----|---------|
| OnOff | 0x0006 | All switches, plugs, bulbs |
| Level Control | 0x0008 | Dimmers, bulbs |
| Color Control | 0x0300 | Color bulbs, strips |
| Scenes | 0x0005 | All devices |
| Groups | 0x0004 | All devices |
| Door Lock | 0x0101 | Locks (if supported) |
| Thermostat | 0x0201 | HVAC devices |
| Fan Control | 0x0202 | Fans |
| Window Covering | 0x0102 | Blinds/shades |

---

## Device Capabilities Matrix

| Device Type | On/Off | Dimming | Color | Temp | Scenes | Groups |
|-------------|--------|---------|-------|------|--------|--------|
| Full Color Bulb | X | X | X | X | X | X |
| Tunable White Bulb | X | X | - | X | X | X |
| Soft White Bulb | X | X | - | - | X | X |
| Color Strip | X | X | X | X | X | X |
| Dimmer Switch | X | X | - | - | X | X |
| On/Off Switch | X | - | - | - | X | X |
| Smart Plug | X | - | - | - | X | X |

---

## Provisioning States

| State | Description |
|-------|-------------|
| `PrepareToInstallOutdoorLightStrip` | Pre-install state |
| `COMMISSIONING_STATE_Commissioning` | Active commissioning |
| `CommissioningParameters is empty` | Error state |
| `notify provisioning error check` | Error notification |
| `Invalid unprovisioned beacon data` | BLE error |

---

## Device Identifiers

### Tuya-style

```
devId - Device ID
nodeId - Node ID (mesh)
meshId - Mesh network ID
xlinkId - Xlink device ID
tuyaUserId - Tuya user binding
```

### Matter-style

```
nodeId - Matter node ID
fabricId - Fabric identifier
endpointId - Endpoint on device
vendorId - Vendor ID
productId - Product ID
```

---

*Generated by Kawaiidra MCP*
*Analysis Date: 2026-01-11*
