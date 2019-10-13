#!/bin/bash

CURPATH=${PWD}
ARG1=$1

if [[ $ARG1 == clean ]];then
    rm -rf ${CURPATH}/target
    exit 0
fi

mkdir -p ${CURPATH}/target
cd  target
cmake ${CURPATH}  -DCMAKE_BUILD_TYPE=Release
make

