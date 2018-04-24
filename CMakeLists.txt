project(ed25519)

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
		src/sha512.c
)

add_library(ed25519 STATIC ${SOURCE})

add_executable(ed25519_test test.c)
target_link_libraries(ed25519_test ed25519)