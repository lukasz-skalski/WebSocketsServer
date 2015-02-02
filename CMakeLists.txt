cmake_minimum_required(VERSION 2.6)

project(WebSocketsServer)

enable_language(C)

set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -DDEBUG -g -O0 -pipe")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -O2 -pipe -fomit-frame-pointer")

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(WEBSOCK  REQUIRED libwebsockets)
pkg_check_modules(JSON REQUIRED jansson)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GIO2 REQUIRED gio-2.0)

add_definitions(${OpenSSL_CFLAGS} ${WEBSOCK_CFLAGS} ${JSON_CFLAGS} ${GLIB2_CFLAGS} ${GIO2_CFLAGS})

set(SRCS WebSocketsServer.c)

add_executable(${PROJECT_NAME} ${SRCS})
target_link_libraries(${PROJECT_NAME} ${OpenSSL_LDFLAGS} ${WEBSOCK_LDFLAGS} ${JSON_LDFLAGS} ${GLIB2_LDFLAGS} ${GIO2_LDFLAGS})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION usr/bin)
