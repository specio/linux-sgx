#!/bin/sh
set -e
docker build --target ra_sample --build-arg https_proxy=$https_proxy \
              --build-arg http_proxy=$http_proxy -t sgx_ra_sample -f ./Dockerfile ../

# expecting aesm and its socket are available from another container
# change /dev/isgx to /dev/sgx for DCAP driver
docker run --env http_proxy --env https_proxy --device=/dev/isgx -v /tmp/aesmd:/var/run/aesmd -it sgx_ra_sample
