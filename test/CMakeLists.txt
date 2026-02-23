# Реєструємо папку з тестами як компонент
idf_component_register(
    SRCS "test_logic.c"
    INCLUDE_DIRS "."
    REQUIRES unity nvs_flash esp_wifi
)

# Дозволяємо тестам бачити функції з папки main
# Це потрібно, щоб протестувати save_nvs_str
idf_component_get_property(main_lib main COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} PUBLIC ${main_lib})