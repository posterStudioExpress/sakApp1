cmake_minimum_required(VERSION 3.15)
project(PrinterTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure we build a console executable, not Windows GUI:
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")

add_executable(PrinterTool main.cpp)

target_link_libraries(PrinterTool PRIVATE
  ws2_32    # Winsock
  snmpapi   # SnmpStartup / SnmpCleanup
  mgmtapi   # SnmpMgrOpen / SnmpMgrRequest / SnmpMgrStrToOid / SnmpMgrClose
)
