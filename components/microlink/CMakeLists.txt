file(GLOB SOURCES "src/*.c")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/microlink_disco_zerocopy.c")

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS "include"
    REQUIRES wireguard_lwip esp_netif lwip mbedtls nvs_flash esp_wifi esp_event log json esp_http_client esp_timer
)

# Added -Wno-stringop-overread and -Wno-type-limits to handle the new crypto/math errors
target_compile_options(${COMPONENT_LIB} PRIVATE 
    "-Wno-format" 
    "-Wno-error=format="
    "-Wno-unused-variable"
    "-Wno-unused-function"
    "-Wno-unused-but-set-variable"
    "-Wno-implicit-function-declaration"
    "-Wno-stringop-overread"
    "-Wno-type-limits"
)
