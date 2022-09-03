.PHONY: cert docker
cert:
	mkdir -p cert/
	openssl genrsa -out cert/id_rsa 4096
	openssl rsa -in cert/id_rsa -pubout -out cert/id_rsa.pub

docker:
	docker build -t workflow-jwt-creator .