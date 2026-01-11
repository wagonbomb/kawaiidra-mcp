# GE Cync Smart Home App - Binary Analysis Report

**Target**: com.ge.cbyge (GE Cync)
**Version**: 6.20.0.54634-60b11b1f5
**Platform**: Android (arm64-v8a, armeabi-v7a)
**Analysis Date**: 2026-01-11
**Analyst**: Kawaiidra MCP + Claude Opus 4.5

---

## Executive Summary

The GE Cync app is a sophisticated smart home platform built on **Tuya's Thingclips SDK** with added **Matter/CHIP protocol** support. It manages lighting devices via multiple protocols: WiFi direct, Bluetooth Mesh (SigMesh), Matter over Thread/WiFi, and legacy Xlink cloud.

### Key Findings
- Dual backend: Tuya cloud + GE's Xlink infrastructure
- Full Matter/CHIP SDK implementation (27MB native library)
- Tuya-style datapoint model for device control
- Multiple provisioning paths: BLE, WiFi, Matter QR codes
- Voice assistant integration: Alexa, Google Home
- Camera support via Yi/Kami SDK

---

## 1. Architecture Overview

### 1.1 Application Structure

```
com.ge.cbyge (175MB APK)
├── DEX Files (8 total, ~58MB)
│   ├── classes.dex - Core app, Matter SDK bindings
│   ├── classes2.dex - Tuya SDK, device controllers
│   ├── classes3.dex - UI components, Compose
│   └── classes4-8.dex - Libraries, resources
│
├── Native Libraries (arm64-v8a)
│   ├── libCHIPController.so (27MB) - Matter/CHIP protocol
│   ├── libSetupPayloadParser.so (225KB) - QR/manual codes
│   ├── libBleLib.so (16KB) - Tuya BLE protocol
│   ├── libthing_security.so (79KB) - Tuya API crypto
│   ├── libThingCameraSDK.so (2.4MB) - Camera streaming
│   └── libThingP2PSDK.so (1.6MB) - P2P connections
│
└── Assets
    ├── countryList.en.json
    └── p2p-sdk_app_module.json
```

### 1.2 SDK Dependencies

| SDK | Vendor | Purpose |
|-----|--------|---------|
| Thingclips SDK | Tuya | Core IoT platform |
| CHIP SDK | CSA | Matter protocol |
| Xlink SDK | GE/Xlink | Legacy cloud control |
| Yi/Kami SDK | Xiaoyi | Camera integration |
| Firebase | Google | Analytics, messaging |
| MLKit | Google | QR code scanning |

---

## 2. Onboarding & Provisioning

### 2.1 Matter Commissioning

The app implements full Matter commissioning via the CHIP SDK.

**Setup Payload Parser (libSetupPayloadParser.so)**

```c
// JNI function to parse Matter QR codes
Java_chip_setuppayload_SetupPayloadParser_fetchPayloadFromQrCode(
    JNIEnv *env, jobject obj, jstring qrCode, jboolean allowTestPayload)
{
    // Parses MT: prefixed QR codes
    // Extracts: discriminator, passcode, vendor ID, product ID
    // Returns SetupPayload object or throws SetupPayloadException
}

// Manual 11-digit pairing code parser
Java_chip_setuppayload_SetupPayloadParser_fetchPayloadFromManualEntryCode(...)
```

**Commissioning Flow**

| Step | Function | Description |
|------|----------|-------------|
| 1 | `discoverCommissionableNodes()` | mDNS discovery |
| 2 | `openPairingWindow()` | Open device for pairing |
| 3 | `pairDevice()` | PASE session establishment |
| 4 | `updateCommissioningNetworkCredentials()` | Send WiFi/Thread creds |
| 5 | `commissionDevice()` | Complete commissioning |
| 6 | `onCommissioningComplete()` | Callback on success |

**Key DEX Functions**

```
commissionDevice @ 5055b010
continueCommissioning @ 5055b034
discoverCommissionableNodes @ 5055b058
onCommissioningComplete @ 5055b298
onCommissioningStatusUpdate @ 5055b2b8
openPairingWindow @ 5055ad30
pairDevice @ 5055b460
unpairDevice @ 5055ba78
```

### 2.2 BLE Provisioning (Tuya)

**Session Key Generation (libBleLib.so)**

```c
void made_session_key(byte *device_key, byte key_len, byte *session_key)
{
    // XOR operation with CRC8 lookup table
    // Generates 16-byte session key
    for (int i = 0; i < 16; i++) {
        if (i < key_len) {
            value = session_key[i];
        } else {
            value = device_key[i - key_len] + device_key[i - key_len + 1];
        }
        session_key[i] = crc8_table[device_key[i] ^ value];
    }
}
```

**BLE JNI Functions**

| Function | Purpose |
|----------|---------|
| `getNormalRequestData` | Basic BLE requests |
| `getCommandRequestData` | Command with KLV encoding |
| `parseDataRecived` | Parse incoming data |
| `madeSessionKey` | Generate encryption key |
| `parseKLVData` | Decode Key-Length-Value |
| `crc4otaPackage` | OTA packet checksum |

**KLV Protocol**

The BLE protocol uses Key-Length-Value encoding:
- Types 0-5 map to different data formats
- Type 0,2,3,4: Variable length with size field
- Type 1,5: Fixed length (1 byte)

### 2.3 SigMesh Provisioning

```
ThingSigMeshProvisioningActivator - Main provisioning class
ThingBlueMeshActivatorStatusImpl - Status callbacks
obtainSigMeshGlobalConfiguration - Mesh config
operateSceneUnderSigmesh - Scene control via mesh
```

### 2.4 Provisioning UI Flow

```
CommissioningBulbTypeFragment
    ↓
CommissioningScanDeviceItem (QR/manual scan)
    ↓
CommissioningAddRoomFragment
    ↓
CommissioningAddGroupFragment
    ↓
CommissioningRevealModeFragment (Reveal bulbs only)
    ↓
CommissioningCaptureWiringFragment
    ↓
CommissioningSelectRoomFragment
    ↓
CommissioningCompleteFragment
```

---

## 3. Lighting Control

### 3.1 Matter Clusters

**OnOff Cluster (0x0006)**

| Function | Address | Description |
|----------|---------|-------------|
| `on()` | 5054e4c0 | Turn on |
| `off()` | 5054e4dc | Turn off |
| `toggle()` | 5054e4f8 | Toggle state |
| `onWithRecallGlobalScene()` | 5054e538 | Restore scene |
| `readOnOffAttribute()` | 5054e6b4 | Get state |
| `writeStartUpOnOffAttribute()` | 5054e978 | Set boot state |

**Level Control Cluster (0x0008)**

| Function | Address | Description |
|----------|---------|-------------|
| `moveToLevel()` | 5054b7a4 | Set brightness |
| `moveToLevelWithOnOff()` | 5054b800 | Set + turn on |
| `move()` | 5054b8b8 | Continuous dim |
| `step()` | 5054b908 | Step dim |
| `stop()` | 5054b950 | Stop dimming |
| `readCurrentLevelAttribute()` | 5054b928 | Get brightness |
| `readMinLevelAttribute()` | 5054ba08 | Get min |
| `readMaxLevelAttribute()` | 5054b9d0 | Get max |
| `writeOnLevelAttribute()` | 5054bfd8 | Set default level |

**Color Control Cluster (0x0300)**

| Function | Address | Description |
|----------|---------|-------------|
| `moveToHue()` | 505431b8 | Set hue |
| `moveToSaturation()` | 50543290 | Set saturation |
| `moveToHueAndSaturation()` | 50543224 | Set H+S |
| `enhancedMoveToHue()` | 50542e20 | 16-bit hue |
| `enhancedMoveToHueAndSaturation()` | 50542e8c | Enhanced H+S |
| `moveToColor()` | 505430f0 | XY color space |
| `moveToColorTemperature()` | 5054315c | Kelvin/Mireds |
| `colorLoopSet()` | 50542db0 | Color cycling |
| `stopMoveStep()` | 50543358 | Stop transition |

**Scenes Cluster (0x0005)**

| Function | Address | Description |
|----------|---------|-------------|
| `addScene()` | 50551904 | Create scene |
| `viewScene()` | 50551e10 | Get scene data |
| `removeScene()` | 50551bb8 | Delete scene |
| `removeAllScenes()` | 50551b68 | Clear all |
| `storeScene()` | 50551c0c | Save current state |
| `recallScene()` | 50551b10 | Activate scene |
| `getSceneMembership()` | 50551970 | List scenes |

### 3.2 Tuya Datapoints

| Datapoint | Code | Type | Range | Description |
|-----------|------|------|-------|-------------|
| `switch_led` | 1 | Boolean | true/false | Power on/off |
| `bright_value` | 2 | Integer | 10-1000 | Brightness |
| `temp_value` | 3 | Integer | 0-1000 | Color temperature |
| `color_data` | 5 | String | HSV JSON | RGB color |
| `scene_data` | 6 | String | Scene JSON | Scene config |
| `countdown1` | 7 | Integer | 0-86400 | Timer (seconds) |
| `work_mode` | 4 | Enum | white/colour/scene | Mode |

**Datapoint Publishing**

```
publishDps() → MQTT → Device
onPublishDpsSuccess() ← ACK
onPublishDpsFail() ← Error
```

### 3.3 Command Structure

```kotlin
// Lighting commands
SetBrightnessCommand(brightness: Int)
WholeBrightnessSetTo(brightness: Int)

// Scene commands
AddAutomationHubCommand(sceneId: String)
CreateScheduleHubCommand(sceneId: String)
DeleteScheduleHubCommand
RemoveDeviceSceneCommand(sceneId: String)

// Group commands
sendCommandToDeviceGroupsUseCase
QueryHubDeviceListCommand
```

---

## 4. Scheduling & Automation

### 4.1 Matter Schedules

**Week Day Schedule**

```
setWeekDaySchedule(userIndex, scheduleIndex, daysMask,
                   startHour, startMinute, endHour, endMinute)
getWeekDaySchedule(userIndex, scheduleIndex)
clearWeekDaySchedule(userIndex, scheduleIndex)
```

**Year Day Schedule**

```
setYearDaySchedule(userIndex, scheduleIndex,
                   localStartTime, localEndTime)
getYearDaySchedule(userIndex, scheduleIndex)
clearYearDaySchedule(userIndex, scheduleIndex)
```

**Holiday Schedule**

```
setHolidaySchedule(holidayIndex, localStartTime,
                   localEndTime, operatingMode)
getHolidaySchedule(holidayIndex)
clearHolidaySchedule(holidayIndex)
```

### 4.2 Tuya Timers

```
TuyaCameraScheduleTimerId(startId, endId)
CreateScheduleHubCommand
DeleteScheduleHubCommand
countdown1 datapoint for simple timers
```

---

## 5. Security Analysis

### 5.1 Tuya Security (libthing_security.so)

**JNI Methods**

| Method | Signature | Purpose |
|--------|-----------|---------|
| `doCommandNative` | `(Context, int, byte[], byte[], boolean) -> Object` | Execute secure command |
| `encryptPostData` | `(String, byte[]) -> byte[]` | Encrypt API payload |
| `decryptResponseData` | `(String, byte[]) -> byte[]` | Decrypt API response |
| `getEncryptoKey` | `(String, String) -> byte[]` | Derive encryption key |
| `genKey` | `(String, String, String) -> String` | Generate signing key |
| `computeDigest` | `(String, String) -> String` | SHA256 digest |
| `getChKey` | `(Context, byte[]) -> String` | Get channel key |
| `getConfig` | `(Context, String, String) -> String` | Get config |
| `securityOpen` | `(Context) -> String` | Initialize security |
| `checkStatus` | `() -> boolean` | Check security status |

**Crypto Implementation**

- **Algorithm**: AES-GCM (via mbedTLS)
- **Digest**: SHA256
- **Encoding**: Base64
- **Key Material**: Embedded in binary (see strings)

**Embedded Key (Base64)**

```
128ZqgoVhKlCsxrh8nW365OwbZHS2dp9AS5zMgsDfcdWB2nBpzIH6eKqkJzGIIXHeRpQJWIGHYG3jfz
XunYJDE3EonrUQhYI1yssR69XawNn3DdFIPGUY4nnnZAlQUae0xuoP9Ud7+C+8Wy8EJlrutktuXzhx
rmD+GsXn2jsA5w17C88L7tn5Mxe9mZvtkfLlxn
```

**Config Files**

| File | Purpose |
|------|---------|
| `t_cdc.tcfg` | Device config |
| `t_s_daily.bmp` | Daily signing key |
| `t_s.bmp` | Production signing key |

### 5.2 Matter Security

- SPAKE2+ for commissioning PASE
- NOC (Node Operational Certificate) chain
- Fabric encryption keys
- ARM64e PAC (Pointer Authentication)

### 5.3 BLE Security

```c
// Session key derivation
made_session_key(device_key, key_len, session_key)
// Uses CRC8 lookup table for obfuscation
// 16-byte output key
```

---

## 6. Network Protocols

### 6.1 Protocol Stack

| Protocol | Transport | Port | Usage |
|----------|-----------|------|-------|
| Matter | Thread/WiFi | 5540 | New devices |
| SigMesh | BLE | - | Bluetooth mesh |
| MQTT | TCP/TLS | 8883 | Real-time sync |
| Xlink | TCP/UDP | Various | Legacy control |
| mDNS | UDP | 5353 | Matter discovery |
| HTTP/S | TCP | 443 | Cloud API |

### 6.2 MQTT Topics

```
// Device status
thing.m.device.push.status.switch
thing.m.msg.notice.switch.status
thing.m.msg.notice.switch.setting

// User events
global_user_event

// Scene updates
monitorSceneUpdateMqtt400
```

### 6.3 API Endpoints

See [ge-cync-api-endpoints.md](ge-cync-api-endpoints.md) for complete list.

---

## 7. Voice Assistant Integration

### 7.1 Amazon Alexa

```
Skill Link: https://pitangui.amazon.com/api/skill/link/MVKN2DE78WD9R
Token URL: https://api.amazon.com/auth/o2/token
Activation: https://api-iot-ge.xlink.cloud/avs/v1/wss/skill-activation
Redirect: https://api-iot-ge.xlink.cloud/avs/v1/user/create_new_redirect_uri
```

**Handler**: `SetAmazonTokenGeCommandHandler.kt`

### 7.2 Google Home

```
OAuth: https://oauth-redirect.googleusercontent.com/r/cbyge-action
Smart Home: https://oauth-redirect.googleusercontent.com/r/smart-home-skill-3322b
```

---

## 8. Device Types

See [ge-cync-device-types.md](ge-cync-device-types.md) for complete catalog.

### 8.1 Summary

| Category | Count | Examples |
|----------|-------|----------|
| Bulbs | 15+ | A19, BR30, G25, ST19 |
| Light Strips | 5+ | Indoor, Outdoor, Neon |
| Switches | 8+ | Paddle, Toggle, Keypad |
| Dimmers | 4+ | 4-wire, No-neutral |
| Plugs | 3+ | Indoor, Outdoor |
| Sensors | 2+ | Motion, Thermostat |

---

## 9. Firmware Updates

### 9.1 OTA System

```kotlin
FirmwareUpdateService - Main update service
FirmwareUpdateEntity(deviceType, currentVersion, updateVersion)
FirmwareUpgradeTaskRequest(type, deviceId, version)
```

### 9.2 Update Types

| Type | Description |
|------|-------------|
| BLE OTA | Direct Bluetooth update |
| WiFi OTA | Over-the-air via WiFi |
| Hub OTA | Via gateway device |

### 9.3 Database Schema

```sql
UPDATE DeviceFirmware SET currentVersion = NULL, currentVersionTimestamp = ?
UPDATE DeviceFirmware SET wifiUpdateVersion = NULL, wifiUpdateTimestamp = ?
```

---

## 10. Native Libraries Reference

| Library | Size | Purpose | Key Functions |
|---------|------|---------|---------------|
| `libCHIPController.so` | 27MB | Matter/CHIP | Full protocol stack |
| `libSetupPayloadParser.so` | 225KB | QR parsing | fetchPayloadFromQrCode |
| `libBleLib.so` | 16KB | BLE protocol | made_session_key, KLV |
| `libthing_security.so` | 79KB | API crypto | encryptPostData, genKey |
| `libthing_security_algorithm.so` | 70KB | Crypto algos | AES, SHA |
| `libmbedtls.so` | 186KB | TLS | GCM, certificates |
| `libmbedcrypto.so` | 562KB | Crypto | AES, SHA, RSA |
| `libThingCameraSDK.so` | 2.4MB | Camera | Streaming, recording |
| `libThingP2PSDK.so` | 1.6MB | P2P | NAT traversal |
| `libThingSmartLink.so` | 47KB | SmartConfig | WiFi provisioning |
| `libnetwork-android.so` | 532KB | Networking | HTTP, sockets |
| `libijkffmpeg.so` | 14MB | FFmpeg | Video decode |
| `libijkplayer.so` | 341KB | Player | Media playback |
| `libtensorflowlite.so` | 2.2MB | ML | On-device inference |

---

## 11. Appendix

### 11.1 Tools Used

- **Kawaiidra MCP** - Ghidra automation
- **Ghidra 12.0** - Decompilation
- **strings** - String extraction
- **unzip** - APK extraction

### 11.2 Analysis Artifacts

```
binaries/cbyge_extracted/
├── classes.dex - classes8.dex
├── lib/arm64-v8a/*.so
├── lib/armeabi-v7a/*.so
├── AndroidManifest.xml (binary)
└── assets/
```

### 11.3 Related Reports

- [API Endpoints Reference](ge-cync-api-endpoints.md)
- [Device Types Catalog](ge-cync-device-types.md)

---

*Generated by Kawaiidra MCP + Claude Opus 4.5*
*Analysis Date: 2026-01-11*
