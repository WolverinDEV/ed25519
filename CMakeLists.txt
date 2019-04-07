project(ed25519)
cmake_minimum_required(VERSION 3.9)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(USE_OPENSSL "Use openssl for sha 512 (Faster than the default installation" ON)

set(SOURCE
		src/add_scalar.c
		src/fe.c
		src/ge.c
		src/key_exchange.c
		src/keypair.c
		src/sc.c
		src/seed.c
		src/sign.c
		src/verify.c
)

if(USE_OPENSSL)
	add_definitions(-DUSE_OPENSSL)
	set(SOURCE ${SOURCE} src/sha512_openssl.c)
else()
	set(SOURCE ${SOURCE} src/sha512.c)
endif()

#Some programs need for full support the header files too
set(HEADERS
		include/ed25519.h
		include/fe.h
		include/fixedint.h
		include/ge.h
		include/precomp_data.h
		include/sc.h
		include/sha512.h
)

add_library(ed25519 STATIC ${SOURCE} ${HEADERS})

add_executable(ed25519_test test.c)
target_link_libraries(ed25519_test ed25519)

if(USE_OPENSSL)
	target_link_libraries(ed25519_test crypto)
endif()

INSTALL(DIRECTORY include/ DESTINATION include/ed25519)
INSTALL(TARGETS ed25519
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
)