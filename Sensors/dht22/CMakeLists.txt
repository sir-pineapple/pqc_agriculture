cmake_minimum_required(VERSION 3.16)

add_compile_options(-Wno-array-parameter)

# KYBER_90S removed — now matches oqs ML-KEM-512 standard
add_compile_definitions("KYBER_K=2")
add_compile_definitions("SHA_ACC=0")
add_compile_definitions("AES_ACC=0")
add_compile_definitions("INDCPA_KEYPAIR_DUAL=0")
add_compile_definitions("INDCPA_ENC_DUAL=0")
add_compile_definitions("INDCPA_DEC_DUAL=0")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dht22_kyber)