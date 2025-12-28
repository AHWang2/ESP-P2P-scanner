/*  WiFi softAP Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"

/* The examples use WiFi configuration that you can set via project configuration menu.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_WIFI_CHANNEL   CONFIG_ESP_WIFI_CHANNEL
#define EXAMPLE_MAX_STA_CONN       CONFIG_ESP_MAX_STA_CONN

#if CONFIG_ESP_GTK_REKEYING_ENABLE
#define EXAMPLE_GTK_REKEY_INTERVAL CONFIG_ESP_GTK_REKEY_INTERVAL
#else
#define EXAMPLE_GTK_REKEY_INTERVAL 0
#endif

static const char *TAG = "wifi softAP";
static const char *P2P_TAG = "P2P_TEST";

// 简化的P2P信息元素
// 完整的P2P IE

// static const uint8_t P2P_IE_Capability[] = {
//     0x02,           // Attribute: Capability ID(0x02)
//     0x02, 0x00,           // Length: xx byte
//     0x14,                 // Capability value: 
//     0x02                 // Group Capability Bitmap field
// };
// static const uint8_t P2P_IE_P2P_Device_ID[] = {
//     0x03,           // Attribute: P2P Device ID (0x0003)
//     0x06, 0x00,           // Length: 6 bytes
//     0x1C, 0xDB, 0xD4, 0xAC, 0x7A, 0x15  // 你的MAC地址
// };
// static const uint8_t P2P_IE_P2P_Group_BSSID[] = {
//     0x04,           // Attribute: P2P Group BSSID (0x0004)
//     0x02, 0x00,           // Length: 2 bytes
// };
// static const uint8_t P2P_beacon_ie_data[] = {
//     // Vendor Specific IE header
//     0xDD,   // Element ID: 0xDD
//     0x17,  // , Length: 23 bytes
    
//     // Wi-Fi Alliance OUI + P2P OUI Type
//     0x50, 0x6F, 0x9A, 0x09,
    
//     // ============ ATTRIBUTE 0x02: Capability ============
//     0x02,           // Attribute: Capability ID(0x02)
//     0x02, 0x00,           // Length: xx byte
//     0x14,                 // Capability value: 
//     0x02,                // Group Capability Bitmap field
    
//     // ============ ATTRIBUTE 0x03: P2P Device ID ============
//     0x03,           // Attribute: P2P Device ID (0x0003)
//     0x06, 0x00,           // Length: 6 bytes
//     0x1C, 0xDB, 0xD4, 0xAC, 0x7A, 0x15,  // 你的MAC地址
    
//     // ============ ATTRIBUTE 0x0C: Notice of Absence ID============
//     0x0C,                   // Attribute: Notice of Absence ID (0x000C)
//     0x02, 0x00,             // Length: 2 bytes
//     0x00,                   // Index: 0
//     0x00,                   // CTWindow & OppPS: OppPS=0, CTWindow=0
    
//     // =========== ATTRIBUTE WSC IE ============
//     0x00 0x50, 0xF2, 0x04, // WSC OUI + Type

//     // 填充到32字节
//     0x00, 0x00, 0x00
// };

// I (896041) P2P_SNIFFER: 检测到 P2P IE! 类型: ProbeResp, 长度: 49
// I (896051) P2P_DATA: dd 31 50 6f 9a 09 02 02 00 04 01 08 04 00 ff ff
// I (896061) P2P_DATA: ff ff 0c 02 00 00 00 0d 19 00 1c db d4 ac 7a 15
// I (896061) P2P_DATA: 00 80 00 0a 00 50 f2 04 00 02 00 10 11 00 04 45
// I (896071) P2P_DATA: 53 50 41

//                       dd 31 50 6f 9a 09 02 02 00 25 00 0d 25 00 be f4
// I (1482081) P2P_DATA: d4 7c 16 6c 10 88 00 03 00 50 f2 04 00 05 00 10
// I (1482091) P2P_DATA: 11 00 10 44 43 50 2d 4a 35 32 36 4e 5f 42 52 39
// I (1482101) P2P_DATA: 36 36 63

// I (896071) P2P_SNIFFER: 检测到 WSC IE! 长度: 109
// I (896081) WSC_DATA: dd 6d 00 50 f2 04 10 4a 00 01 20 10 44 00 01 02
// I (896081) WSC_DATA: 10 3b 00 01 03 10 47 00 10 01 02 03 04 05 06 07
// I (896091) WSC_DATA: 08 09 0a 0b 0c 0d 0e 0f 10 10 21 00 09 45 73 70
// I (896091) WSC_DATA: 72 65 73 73 69 66 10 23 00 07 45 53 50 33 32 53
// I (896101) WSC_DATA: 33 10 24 00 01 31 10 42 00 01 31 10 54 00 08 00
// I (896111) WSC_DATA: 0a 00 50 f2 04 00 02 10 11 00 04 45 53 50 41 10
// I (896111) WSC_DATA: 08 00 02 00 80 10 49 00 06 00 37 2a 00 01 20



static const uint8_t P2P_response_ie_data[] = {
    // Vendor Specific IE header
    0xDD, 0x25,  // Element ID: 0xDD, Length: 37 bytes
    
    // Wi-Fi Alliance OUI + P2P OUI Type
    0x50, 0x6F, 0x9A, 0x09,
    
    // ============ ATTRIBUTE 0x02: Capability ============
    0x02,           // Attribute: Capability (0x02)
    0x02, 0x00,           // Length: 2 byte
    0x21,                 // Capability value: 
    0x01,                // Group Capability Bitmap field
    
    // // ============ ATTRIBUTE 0x08: Extended Listen Timing ============
    // 0x08,               // Attribute: Extended Listen Timing (0x0008)
    // 0x04, 0x00,         // Length: 4 bytes
    // 0xFF, 0xFF,         // Availability Period: continuously available
    // 0xFF, 0xFF,         // Availability Interval: continuously available
    
    // // ============ ATTRIBUTE 0x0C: Notice of Absence ============
    // 0x0C,                   // Attribute: Notice of Absence ID (0x000C)
    // 0x02, 0x00,             // Length: 2 bytes
    // 0x00,                   // Index: 0
    // 0x00,                   // CTWindow & OppPS: OppPS=0, CTWindow=0

    // ============ ATTRIBUTE 0x0D: P2P Device Info ============
    0x0D,
    0x19, 0x00,  // Length: 25 bytes
    0x1C, 0xDB, 0xD4, 0xAC, 0x7A, 0x15,  // MAC address
    0x00, 0x80,  // Config Methods: push button
    0x00, 0x03, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x05, // Primary Device Type
    0x00,           // Number of Secondary Device Types
    0x10, 0x11, 0x00, 0x04, 'E','S','P','A'    // Device Name (keep as same as it in WSC IE)
};

static const uint8_t WSC_response_ie_data[] = {
    // Vendor Specific IE header
    0xDD, 0x6D,  // Element ID: 0xDD, Length: 99 bytes

    // Wi-Fi Alliance OUI + WSC OUI Type
    0x00, 0x50, 0xF2, 0x04,

    // ============ ATTRIBUTE 0x104A: Version ============
    0x10, 0x4A,     // Attribute: Version (0x104A)
    0x00, 0x01,     // Length: 1 bytes
    0x20,           // Version value: WSC version

    // ============ ATTRIBUTE 0x1044: State ============
    0x10, 0x44,     // Attribute: State (0x1044)
    0x00, 0x01,     // Length: 1 byte
    0x02,           // State value: Configured

    // ============ ATTRIBUTE 0x103B: Response Type ============
    0x10, 0x3B,     // Attribute: Response Type (0x103B)
    0x00, 0x01,     // Length: 1 byte
    0x03,           // Response Type value: AP

    // ============ ATTRIBUTE 0x1047: UUID-E ============
    0x10, 0x47,     // Attribute: UUID-E (0x1047)
    0x00, 0x10,     // Length: 16 byte
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,  // UUID-E value: 16 random numbers

    // ============ ATTRIBUTE 0x1021: Manufacturer ============
    0x10, 0x21,     // Attribute: Manufacturer (0x1021)
    0x00, 0x09,     // Length: 9 byte
    'E', 's', 'p', 'r', 'e', 's', 's', 'i', 'f',    // Manufacturer value: espressif
    
    // ============ ATTRIBUTE 0x1023: Model Name ============
    0x10, 0x23,     // Attribute: Model Name (0x1023)
    0x00, 0x07,     // Length: 7 byte
    'E', 'S', 'P', '3', '2', 'S', '3',    // Model Name value: ESP32S3

    // ============ ATTRIBUTE 0x1024: Model Number ============
    0x10, 0x24,     // Attribute: Model Number (0x1024)
    0x00, 0x01,     // Length: 1 byte
    '1',            // Model Number value: 1

    // ============ ATTRIBUTE 0x1042: Serial Number ============
    0x10, 0x42,     // Attribute: Serial Number (0x1042)
    0x00, 0x01,     // Length: 1 byte
    '1',

    // ============ ATTRIBUTE 0x1054: Primary Device Type ============
    0x10, 0x54,     // Attribute: Primary Device Type (0x1054)
    0x00, 0x08,     // Length: 8 byte
    0x00, 0x03, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x05, // Primary Device Type value: P2P Device

    // ============ ATTRIBUTE 0x1011: Device Name ============
    0x10, 0x11,     // Attribute: Device Name (0x1011)
    0x00, 0x04,     // Length: 4 byte
    'E', 'S', 'P', 'A', // Device Name value: ESPA

    // ============ ATTRIBUTE 0x1008: Configuration Methods ============
    0x10, 0x08,     // Attribute: Configuration Methods (0x1008)
    0x00, 0x02,     // Length: 2 byte
    0x00, 0x80,  // Config Methods: push button

    // ============ ATTRIBUTE 0x1049: Vendor Extension ============
    0x10, 0x49,     // Attribute: Vendor Extension (0x1049)
    0x00, 0x06,     // Length: 6 byte
    0x00, 0x37, 0x2A,  // Vendor ID: WFA OUI
    0x00,       // ID: Version 2
    0x01,       // Version 2 length: 1 Byte
    0x20        // Version 2.0.7
};

// 添加P2P IE到Beacon和Probe Response
static void add_p2p_vendor_ies(void) {

    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    ESP_LOGI(TAG, " WDLWDL WDLWDL %02X %02X %02X %02X %02X %02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // add P2P IE to Probe Response frame
    esp_err_t ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_0, P2P_response_ie_data);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set P2P IE to Probe Response: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "P2P IE added to Probe Response");
    }

    // add WSC IE to Probe Response frame
    ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_1, WSC_response_ie_data);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WSC IE to Probe Response: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "WSC IE added to Probe Response");
    }
    return;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d, reason=%d",
                 MAC2STR(event->mac), event->aid, event->reason);
    }
    return;
}

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .ssid_len = strlen(EXAMPLE_ESP_WIFI_SSID),
            .channel = EXAMPLE_ESP_WIFI_CHANNEL,
            .password = EXAMPLE_ESP_WIFI_PASS,
            .max_connection = EXAMPLE_MAX_STA_CONN,
#ifdef CONFIG_ESP_WIFI_SOFTAP_SAE_SUPPORT
            .authmode = WIFI_AUTH_WPA3_PSK,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
#else /* CONFIG_ESP_WIFI_SOFTAP_SAE_SUPPORT */
            .authmode = WIFI_AUTH_WPA2_PSK,
#endif
            .pmf_cfg = {
                    .required = true,
            },
#ifdef CONFIG_ESP_WIFI_BSS_MAX_IDLE_SUPPORT
            .bss_max_idle_cfg = {
                .period = WIFI_AP_DEFAULT_MAX_IDLE_PERIOD,
                .protected_keep_alive = 1,
            },
#endif
            .gtk_rekey_interval = EXAMPLE_GTK_REKEY_INTERVAL,
        },
    };
    if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    vTaskDelay(pdMS_TO_TICKS(100));
    add_p2p_vendor_ies();

    ESP_LOGI(P2P_TAG, "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS, EXAMPLE_ESP_WIFI_CHANNEL);
}

void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();
}
