#build local image for socat
docker build -t socat -f socat_Dockerfile .

#create a container that uses socat to listen and forward requests
# from tcp port 2375 (mapped to host side 2376) to
# aesm socket at /var/run/aesmd/aesm.socket, that is
# mounted from /tmp/aesmd on host
docker run -d --restart=always -v /tmp/aesmd/:/var/run/aesmd \
	-p 127.0.0.1:2376:2375 \
	--name aesmserver \
	socat \
	tcp-listen:2375,fork,reuseaddr unix-connect:/var/run/aesmd/aesm.socket

#create a container that uses socat to listen and forward requests
# from socket at /var/run/aesmd/aesm.socket, that is
# mounted from /tmp/aesm_client on host
# to tcp connection to port 2375 of the aesmserver proxy

docker run -d --restart=always -v /tmp/aesm_client:/var/run/aesmd/ \
	--name aesmclient \
	--link aesmserver \
	socat \
	unix-listen:/var/run/aesmd/aesm.socket,reuseaddr,fork tcp:aesmserver:2375
