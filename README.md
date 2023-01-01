A service that can generate JWTs on a private port, then serve JWKS keys and `/userinfo` calls on a public port.

- 8000: public port
  - GET /.well-known/openid-configuration
  - GET /.well-known/keys
- 8001: private, admin port
  - POST /tokens/jobs/generate

### Generate An RSA private key

Run `make cert` to build private key `cert/id_rsa` and public key `cert/id_rsa.pub`

## Configuring

Configured with a `config.yaml` file in the working directory, or via environment variables

| config key  | env_variable    | description         | default       |
| ----------- | --------------- | ------------------- | ------------- |
| private_key | JWT_PRIVATE_KEY | path to private key | ./cert/id_rsa |
