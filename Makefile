.PHONY: cert docker run
cert:
        mkdir -p cert/
        openssl genrsa -out cert/id_rsa 4096
        openssl rsa -in cert/id_rsa -pubout -out cert/id_rsa.pub

docker:
        docker build -t workflow-jwt-creator .

run:
        docker run --rm --name jwt-maker \
                   -p 8000:8000 -p 8001:8001 \
                   -e JWT_PRIVATE_KEY=/app/cert/id_rsa \
                   -v $(shell pwd)/cert:/app/cert \
                   workflow-jwt-creator