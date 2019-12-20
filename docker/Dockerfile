FROM ubuntu:18.04 as builder

RUN apt-get update --fix-missing
RUN apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev 
RUN apt-get install -y git libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake lsb-release


WORKDIR /linux-sgx
#Assume this docker file will be invoked with root at the top of linux-sgx repo, see shell scripts for example.
ADD . .

RUN ./download_prebuilt.sh

RUN make sdk_install_pkg

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make psw_install_pkg

RUN make deb_pkg

FROM ubuntu:18.04 as aesm 
RUN apt-get update && \ 
    apt-get install -y libssl1.1 libcurl4 libprotobuf10 module-init-tools make
 
WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin
USER aesmd
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon

FROM ubuntu:18.04 as aesm_deb

RUN apt-get update && \
    apt-get install -y libssl1.1 libcurl4 libprotobuf10 module-init-tools make
 
WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/deb/*.deb ./

RUN  dpkg -i ./libsgx-enclave-common_*_amd64.deb
USER aesmd
WORKDIR /opt/intel/libsgx-enclave-common/aesm
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


FROM ubuntu:18.04 as sample
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf-dev \
                       libssl-dev \
                       make \
                       module-init-tools
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

CMD ./app

FROM ubuntu:18.04 as sample_deb
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf-dev \
                       libssl-dev \
                       make \
                       module-init-tools
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/deb/*.deb ./
RUN  dpkg -i ./libsgx-enclave-common_*_amd64.deb
RUN  dpkg -i ./libsgx-urts_*_amd64.deb

COPY --from=builder /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk*.bin ./
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

CMD ./app


FROM ubuntu:18.04 as ra_sample
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf-dev \
                       libssl-dev \
                       make \
                       module-init-tools
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/RemoteAttestation
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make
ENV LD_LIBRARY_PATH=sample_libcrypto

CMD ./app
