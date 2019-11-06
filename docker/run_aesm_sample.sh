docker container rm sgx_all
docker create --name sgx_all --entrypoint="/opt/intel/aesm_sample_wrapper.sh" --env http_proxy --env https_proxy --device=/dev/isgx -v /tmp/aesmd:/var/run/aesmd sgx_sample
docker cp aesm_sample_wrapper.sh sgx_all:/opt/intel/aesm_sample_wrapper.sh
docker start -a -i sgx_all  
