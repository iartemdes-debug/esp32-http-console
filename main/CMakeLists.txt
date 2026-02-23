idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi nvs_flash esp_event esp_http_client console driver)   
