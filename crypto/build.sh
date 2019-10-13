#!/bin/bash

CURPATH=${PWD}
ARG1=$1
BUILDTYPE=Release

if [[ $ARG1 == clean ]];then
    rm -rf ${CURPATH}/target
    exit 0
elif [[ $ARG1 == debug ]];then
    BUILDTYPE=Debug
fi

mkdir -p ${CURPATH}/target
cd  target
cmake ${CURPATH}  -DCMAKE_BUILD_TYPE=${BUILDTYPE}
make

if [[ ! -f cryptotest ]];then
    echo "build cryptoo fail"
    exit 1
fi
./cryptotest
exit 0