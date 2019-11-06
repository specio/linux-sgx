#!/bin/sh
cd /opt/intel/sgxpsw/aesm/
export LD_LIBRARY_PATH=.
./aesm_service --no-daemon &
echo "wait 10s for aesm_service to start up..."
sleep 10
echo "starting app..."
cd /opt/intel/sgxsdk/SampleCode/SampleEnclave
./app



