#include <stdio.h>               // For standard input/output functions 
#include <string.h>              // For standard input/output and string functions
#include "freertos/FreeRTOS.h"   // For FreeRTOS types and functions 
#include "freertos/task.h"       // For FreeRTOS tasks and delays 
#include "esp_system.h"          // For system functions
#include "esp_wifi.h"            // For WiFi functions
#include "esp_wifi_types.h"      // For WiFi data types
#include "esp_event.h"           // For WiFi and event handling
#include "esp_log.h"             // For logging
#include "nvs.h"                 // For NVS (Non-Volatile Storage) functions
#include "nvs_flash.h"           // For NVS flash initialization
#include "esp_console.h"         // For console REPL
#include "esp_vfs_dev.h"         // For UART console
//#include "esp_vfs_fat.h"         // For FAT filesystem (if needed for future extensions)
#include "driver/uart.h"         // For UART console 
#include "linenoise/linenoise.h" // For command line editing and history
#include "esp_http_client.h"     // For HTTP client functions 
#include "lwip/err.h"            // For ESP_ERR_ codes
#include "lwip/sys.h"            // For sys_msleep()

// --- NVS Helper Functions ---
// Ці функції допомагають зберігати та вивантажувати рядки в NVS, що використовується для збереження Wi-Fi даних
// Функція для збереження рядка в NVS за ключем
esp_err_t save_nvs_str(const char* key, const char* value) {
    if (value == NULL || key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Валідація довжини відповідно до стандартів Wi-Fi (SSID макс 32, PASS макс 64)
    size_t len = strlen(value);
    if (strcmp(key, "wifi_ssid") == 0 && len > 32) {
        printf("Помилка: SSID занадто довгий (макс 32 символи)!\n");
        return ESP_ERR_INVALID_SIZE;
    }
    if (strcmp(key, "wifi_pass") == 0 && len > 64) {
        printf("Помилка: Пароль занадто довгий (макс 64 символи)!\n");
        return ESP_ERR_INVALID_SIZE;
    }

    nvs_handle_t my_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) return err;

    err = nvs_set_str(my_handle, key, value);
    if (err == ESP_OK) {
        err = nvs_commit(my_handle);
    }

    nvs_close(my_handle);
    return err;
}
// Функція для завантаження рядка з NVS за ключем
esp_err_t load_nvs_str(const char* key, char* out_value, size_t max_size) {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &my_handle);
    if (err != ESP_OK) return err;
    err = nvs_get_str(my_handle, key, out_value, &max_size);
    nvs_close(my_handle);
    return err;
}
// --- Command: reset_nvs ---
// Ця команда очищає всю пам'ять NVS, включаючи збережені Wi-Fi дані. Використовуйте з обережністю!
static int do_reset_nvs_cmd(int argc, char **argv) {
    nvs_flash_erase();
    nvs_flash_init();
    printf("Пам'ять ПЗУ очищена. Після рестарту дані Wi-Fi зникнуть.\n");
    return 0;
}
// --- Command: restart ---
// Ця команда перезавантажує пристрій, що дозволяє застосувати нові налаштування Wi-Fi після їх зміни або просто перезапустити систему.
static int do_restart_cmd(int argc, char **argv) {
    printf("Перезавантаження пристрою...\n");
    vTaskDelay(pdMS_TO_TICKS(500)); // Коротка затримка, щоб встигнути вивести текст в UART
    esp_restart();
    return 0;
}
// --- Command: scan ---
// Ця команда виконує сканування Wi-Fi мереж поблизу та виводить їх SSID, 
// рівень сигналу (RSSI) та тип аутентифікації. Це корисно для перевірки доступних мереж та їх характеристик перед підключенням.
static int do_scan_cmd(int argc, char **argv) {
    printf("Сканування Wi-Fi мереж...\n");

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false
    };

    // Починаємо сканування (блокуючий виклик)
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));

    uint16_t number = 20; // Максимальна кількість мереж для виводу
    wifi_ap_record_t ap_info[20];
    uint16_t ap_count = 0;

    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));

    printf("Знайдено мереж: %u\n", ap_count);
    printf("%-32s | %-7s | %s\n", "SSID", "RSSI", "AUTH");
    printf("------------------------------------------------------------\n");

    for (int i = 0; i < number; i++) {
        printf("%-32s | %-7d | %d\n", 
               (char *)ap_info[i].ssid, 
               ap_info[i].rssi, 
               ap_info[i].authmode);
    }
    return 0;
}
// --- Command: set_wifi <ssid> <pass> ---
// Ця команда дозволяє користувачу ввести SSID та пароль Wi-Fi через консоль, які потім зберігаються в NVS для подальшого використання при підключенні до мережі.
static int do_set_wifi_cmd(int argc, char **argv) {
    if (argc < 3) {
        printf("Помилка: потрібно вказати SSID та PASS. Приклад: set_wifi MyRouter 12345678\n");
        return 1;
    }
    save_nvs_str("wifi_ssid", argv[1]);
    save_nvs_str("wifi_pass", argv[2]);
    printf("Дані Wi-Fi збережено в ПЗУ. Перезавантажте пристрій (restart).\n");
    return 0;
}
// --- Command: get_wifi ---
// Ця команда виводить збережені в NVS SSID та пароль Wi-Fi, якщо вони існують. Якщо дані відсутні, повідомляє про це користувача.
static int do_get_wifi_cmd(int argc, char **argv) {
    char ssid[33] = {0};
    char pass[64] = {0};
    if (load_nvs_str("wifi_ssid", ssid, sizeof(ssid)) == ESP_OK &&
        load_nvs_str("wifi_pass", pass, sizeof(pass)) == ESP_OK) {
        printf("Збережений SSID: %s\n", ssid);
        printf("Збережений PASS: %s\n", pass);
    } else {
        printf("Дані Wi-Fi відсутні в ПЗУ.\n");
    }
    return 0;
}
// --- WiFi Event Handler with Detailed Error Handling ---
// Ця функція розширює базовий обробник Wi-Fi подій, додаючи детальну обробку помилок при відключенні. 
// Вона аналізує код причини відключення та виводить конкретні повідомлення про помилки, такі як неправильний пароль або відсутність мережі,
// а також намагається автоматично повторно підключитися при інших типах помилок.
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t* event = (wifi_event_sta_disconnected_t*) event_data;
        printf("\n[WiFi] Помилка підключення. Код причини: %d\n", event->reason);

        switch (event->reason) {
            case WIFI_REASON_AUTH_EXPIRE:
            case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
            case WIFI_REASON_BEACON_TIMEOUT:
            case WIFI_REASON_AUTH_FAIL:
                printf("[GENIY] Помилка: Невірний пароль (Auth Fail).\n");
                break;
            case WIFI_REASON_NO_AP_FOUND:  
                printf("[GENIY] Помилка: Мережу не знайдено (SSID not found).\n");
                break;
            default:
                printf("[GENIY] Спроба повторного підключення...\n");
                esp_wifi_connect();
                break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        printf("\n[WiFi] Успішно! Отримано IP: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        printf("geniy> "); // Повертаємо промпт
    }
}
// --- WiFi Initialization (Basic) ---
void wifi_init_basic(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Реєстрація обробників подій
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}
static int do_info_cmd(int argc, char **argv) {
    printf("\n=== ІНФОРМАЦІЯ ПРО СИСТЕМУ ===\n");
    printf("Версія ПЗ: 1.0.2 (test)\n");

    // Отримання вільної оперативної пам'яті
    uint32_t free_heap = esp_get_free_heap_size();
    uint32_t min_free_heap = esp_get_minimum_free_heap_size();
    printf("Вільна пам'ять (Heap): %lu байт\n", free_heap);
    printf("Мінімум вільної пам'яті від старту: %lu байт\n", min_free_heap);

    // Отримання інформації про Wi-Fi
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        printf("Підключено до SSID: %s\n", ap_info.ssid);
        printf("Сила сигналу (RSSI): %d dBm ", ap_info.rssi);
        
        // Маленька візуалізація якості
        if (ap_info.rssi >= -50) printf("(Відмінно)\n");
        else if (ap_info.rssi >= -70) printf("(Добре)\n");
        else printf("(Слабкий сигнал)\n");
    } else {
        printf("Статус Wi-Fi: Не підключено\n");
    }
    
    printf("==============================\n");
    return 0;
}
// --- HTTP Client Event Handler ---
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // Print response body directly to console
                printf("%.*s", evt->data_len, (char*)evt->data);
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}
// --- HTTP Command Logic ---
static int do_http_cmd(int argc, char **argv) {
    // Перевірка, чи ми підключені (чи є IP)
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        printf("Помилка: Немає підключення до мережі. Спершу підключіться до Wi-Fi.\n");
        return 1;
    }
    if (argc < 3) {
        printf("Error: Missing arguments.\n");
        printf("Usage: http <GET|POST> <URL> [BODY]\n");
        return 1;
    }

    const char *method_str = argv[1];
    const char *url = argv[2];
    const char *body = (argc > 3) ? argv[3] : NULL;
    // Визначення HTTP методу
    esp_http_client_method_t method = HTTP_METHOD_GET;
    if (strcasecmp(method_str, "POST") == 0) {
        method = HTTP_METHOD_POST;
    } else if (strcasecmp(method_str, "GET") != 0) {
        printf("Error: Unsupported method. Use GET or POST.\n");
        return 1;
    }
    // Конфігурація HTTP клієнта 
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .timeout_ms = 5000,
    };
    // Ініціалізація HTTP клієнта та виконання запиту
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        printf("Error: Failed to initialize HTTP client\n");
        return 1;
    }
    // Встановлення методу та, якщо це POST, встановлення тіла запиту
    esp_http_client_set_method(client, method);
    // Якщо це POST запит і є тіло, встановлюємо його та відповідний заголовок
    if (method == HTTP_METHOD_POST && body != NULL) {
        esp_http_client_set_post_field(client, body, strlen(body));
        esp_http_client_set_header(client, "Content-Type", "application/json"); // Defaulting to JSON/text
    }
    // Виконання HTTP запиту та обробка результату
    printf("\n--- Sending %s request to %s ---\n", method_str, url);
    esp_err_t err = esp_http_client_perform(client);
    
    if (err == ESP_OK) {
        printf("\n\nStatus = %d, Content Length = %lld\n",
               esp_http_client_get_status_code(client),
               esp_http_client_get_content_length(client));
    } else {
        printf("HTTP request failed: %s\n", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return 0;
}

// --- Console Init ---
static void console_init(void) {
    // 1. Налаштування REPL (інтерфейсу командного рядка)
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = ">>> "; 
    repl_config.max_cmdline_length = 512;

    // 2. Налаштування заліза UART
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    
    // 3. Реєстрація нашої команд ДО запуску (бажано)
    esp_console_cmd_t cmd = {
        .command = "http",
        .help = "Send HTTP request. Usage: http <GET/POST> <URL> <BODY>",
        .hint = NULL,
        .func = &do_http_cmd, 
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
    const esp_console_cmd_t scan_cmd = {
        .command = "scan",
        .help = "Scan for Wi-Fi networks.",
        .hint = NULL,
        .func = &do_scan_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_cmd));
    esp_console_cmd_t cmd_set_wifi = {
        .command = "set_wifi",
        .help = "Set Wi-Fi credentials. Usage: set_wifi <SSID> <PASS>",
        .hint = NULL,
        .func = &do_set_wifi_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd_set_wifi));
    esp_console_cmd_t cmd_get_wifi = {
        .command = "get_wifi",
        .help = "Get saved Wi-Fi credentials.",
        .hint = NULL,
        .func = &do_get_wifi_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd_get_wifi));
    const esp_console_cmd_t restart_cmd = {
        .command = "restart",
        .help = "Restart the device.",
        .hint = NULL,
        .func = &do_restart_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&restart_cmd));
    const esp_console_cmd_t reset_nvs_cmd = {
        .command = "reset_nvs",
        .help = "Erase all NVS data (including Wi-Fi credentials). Use with caution!",
        .hint = NULL,
        .func = &do_reset_nvs_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&reset_nvs_cmd));
    const esp_console_cmd_t info_cmd = {
        .command = "info",
        .help = "Display system information.",
        .hint = NULL,
        .func = &do_info_cmd,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&info_cmd));
    // 4. Створення та АВТОМАТИЧНИЙ запуск REPL
    // В IDF v5.x ця функція сама запускає внутрішню задачу для роботи з консоллю
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));
    
    printf("\n--- Console Initialized. Type 'help' for commands ---\n");
}

void app_main(void) {
    // 1. Ініціалізація NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Ініціалізуємо Wi-Fi стек один раз на старті, але не підключаємось
    wifi_init_basic(); 

    console_init();

    char ssid[33] = {0};
    char pass[64] = {0};
    
    if (load_nvs_str("wifi_ssid", ssid, sizeof(ssid)) == ESP_OK) {
        load_nvs_str("wifi_pass", pass, sizeof(pass));
        printf("Підключення до: %s\n", ssid);
        
        wifi_config_t wifi_config = {0};
        strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        strncpy((char*)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
        
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
        ESP_ERROR_CHECK(esp_wifi_connect()); 
    } else {
        printf("\nWi-Fi не налаштовано. Введіть 'scan' або 'set_wifi'.\n");
    }
}