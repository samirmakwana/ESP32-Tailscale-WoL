# MicroLink Sensor Node Example
cmake_minimum_required(VERSION 3.16)

# Add microlink component path
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/../.."           # microlink component
    "${CMAKE_CURRENT_SOURCE_DIR}/../../components" # wireguard_lwip, json
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(microlink_sensor_node)
