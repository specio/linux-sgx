# expecting aesm socket exposed at /tmp/aesm_client on host. For example:
#
# ../build_and_run_aesm_docker.sh
#
# ./set_up_aesm_socat.sh

# change /dev/isgx to /dev/sgx for DCAP driver
docker run --env http_proxy --env https_proxy --device=/dev/isgx -v /tmp/aesm_client:/var/run/aesmd -it sgx_sample
