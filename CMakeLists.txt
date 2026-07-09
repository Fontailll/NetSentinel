cmake_minimum_required(VERSION 3.14)
project(NetWatch VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
elseif(UNIX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    if(STATIC_LINK)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
endif()

add_library(netwatch_common OBJECT
    src/scanner.cpp
    src/output.cpp
    src/risk.cpp
    src/json_export.cpp
    src/firewall.cpp
    src/utils.cpp
    src/geoip.cpp
    src/daemon.cpp
)

target_include_directories(netwatch_common PUBLIC include)
if(WIN32)
    target_include_directories(netwatch_common PRIVATE platform/windows)
else()
    target_include_directories(netwatch_common PRIVATE platform/linux)
endif()

if(WIN32)
    add_library(netwatch_platform OBJECT
        platform/windows/windows_scanner.cpp
        platform/windows/win_proc.cpp
        platform/windows/win_firewall.cpp
        platform/windows/signature.cpp
    )
    target_include_directories(netwatch_platform PUBLIC platform/windows include)
    target_link_libraries(netwatch_platform PUBLIC
        iphlpapi ws2_32 advapi32 ole32 oleaut32
    )
else()
    add_library(netwatch_platform OBJECT
        platform/linux/linux_scanner.cpp
        platform/linux/lin_proc.cpp
        platform/linux/lin_firewall.cpp
        platform/linux/signature.cpp
    )
    target_include_directories(netwatch_platform PUBLIC platform/linux include)
endif()

add_executable(netwatch
    src/main.cpp
    $<TARGET_OBJECTS:netwatch_common>
    $<TARGET_OBJECTS:netwatch_platform>
)

target_include_directories(netwatch PRIVATE include)

if(WIN32)
    target_link_libraries(netwatch PRIVATE
        iphlpapi ws2_32 advapi32 ole32 oleaut32 wintrust crypt32
    )
endif()

add_executable(netwatch_tests
    tests/test_main.cpp
    tests/test_risk.cpp
    tests/test_geoip.cpp
    tests/test_utils.cpp
    $<TARGET_OBJECTS:netwatch_common>
    $<TARGET_OBJECTS:netwatch_platform>
)

target_include_directories(netwatch_tests PRIVATE include tests)

if(WIN32)
    target_link_libraries(netwatch_tests PRIVATE
        iphlpapi ws2_32 advapi32 ole32 oleaut32 wintrust crypt32
    )
endif()

install(TARGETS netwatch netwatch_tests RUNTIME DESTINATION bin)
