idf_component_register(SRCS "kem.c"
                    INCLUDE_DIRS "." "../common"
                    REQUIRES "indcpa" "verify" "symmetric" "randombytes")

# Kyber512 standard variant (SHAKE/SHA3) — matches liboqs on the Pi.
# KYBER_90S intentionally removed so both sides use identical primitives.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    KYBER_K=2
)