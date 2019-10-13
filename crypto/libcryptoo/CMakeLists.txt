set(LIBRARY_OUTPUT_PATH ${TOP_PATH}/target)

include_directories(
${TOP_PATH}/include
${TOP_PATH}/libcryptoo
)

aux_source_directory(${TOP_PATH}/libcryptoo/aes SRC_LISTS)
aux_source_directory(${TOP_PATH}/libcryptoo/des SRC_LISTS)
aux_source_directory(${TOP_PATH}/libcryptoo/md5 SRC_LISTS)
aux_source_directory(${TOP_PATH}/libcryptoo/sha SRC_LISTS)

add_library(cryptoo STATIC ${SRC_LISTS})
