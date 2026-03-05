# UDP Netcat Example
# Bidirectional UDP over Tailscale VPN

cmake_minimum_required(VERSION 3.16)

# Include MicroLink component
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../components/microlink"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../components/microlink/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(udp_netcat_example)
