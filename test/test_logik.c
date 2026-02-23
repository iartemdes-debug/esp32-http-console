#include "unity.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "string.h"

// Тестуємо функції збереження/завантаження, у main.c, тому оголошуємо їх як extern для доступу в тестах
extern esp_err_t save_nvs_str(const char* key, const char* value);
extern esp_err_t load_nvs_str(const char* key, char* out_value, size_t max_size);

// Функція, яка виконується ПЕРЕД кожним тестом
void setUp(void) {
    nvs_flash_init();
}

// Функція, яка виконується ПІСЛЯ кожного тесту
void tearDown(void) {
    nvs_flash_erase();
}

// ТЕСТ 1: Перевірка збереження та зчитування SSID
void test_nvs_save_load_wifi_credentials(void) {
    const char* test_ssid = "MyRouter";
    const char* test_pass = "password123";
    char loaded_ssid[33] = {0};
    char loaded_pass[64] = {0};

    TEST_ASSERT_EQUAL(ESP_OK, save_nvs_str("wifi_ssid", test_ssid));
    TEST_ASSERT_EQUAL(ESP_OK, save_nvs_str("wifi_pass", test_pass));

    TEST_ASSERT_EQUAL(ESP_OK, load_nvs_str("wifi_ssid", loaded_ssid, sizeof(loaded_ssid)));
    TEST_ASSERT_EQUAL_STRING(test_ssid, loaded_ssid);
}

// ТЕСТ 2: Перевірка обробки некоректних ключів у NVS
void test_nvs_non_existent_key(void) {
    char buffer[32];
    esp_err_t err = load_nvs_str("non_existent", buffer, sizeof(buffer));
    TEST_ASSERT_EQUAL(ESP_ERR_NVS_NOT_FOUND, err);
}

// ТЕСТ 3: Перевірка довжини SSID (макс 32 символи)
void test_wifi_ssid_length_validation(void) {
    char long_ssid[35];
    memset(long_ssid, 'A', 34);
    long_ssid[34] = '\0';
    
    // Перевіряємо, чи поверне наша логіка помилку при спробі зберегти занадто довгий SSID
    esp_err_t err = save_nvs_str("wifi_ssid", long_ssid);
    // Якщо ми додали перевірку в код, тест має пройти успішно (якщо err == ESP_ERR_INVALID_ARG)
    TEST_ASSERT_NOT_EQUAL(ESP_OK, err);
}

void run_logic_tests(void) {
    UNITY_BEGIN();
    RUN_TEST(test_nvs_save_load_wifi_credentials);
    RUN_TEST(test_nvs_non_existent_key);
    RUN_TEST(test_wifi_ssid_length_validation);
    UNITY_END();
}