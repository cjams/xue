#!/bin/bash

if [[ $# -ne 1 ]];
then
    echo "USAGE: ./read.sh /dev/ttyUSB<n>"
    exit 22
fi

while [[ ! -e $1 ]];
do
    sudo lsusb -vv > /dev/null 2>&1
    sleep 0.001
done

cat < $1
