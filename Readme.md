# Keycloak HSM Crypki
Keycloak Extension, which uses [Crypki Service](https://github.com/theparanoids/crypki) for signing with an underlying HSM (Hardware Security Module) or other PKCS #11 device.
This Extension is based on the [Keycloak HSM Extension](https://github.com/denniskniep/keycloak-hsm).

## Showcase

### Quickstart
```
sudo docker-compose up
```

### Configure
* Open http://localhost:8080/admin/master/console/
* Navigate to "Realm Settings > Keys > Providers"
* Click "Add Provider"
* Choose "crypki-hsm"
* Set following values:
```
URL: https://crypki:4443
Name: sign-blob-key
mTLS CA Certificate Path: /opt/keycloak/crypki/tls-crt/ca.crt
mTLS Client Certificate Path: /opt/keycloak/crypki/tls-crt/client.crt
mTLS Client Private Key Path: /opt/keycloak/crypki/tls-crt/client.key
Server Certificate Path: /opt/keycloak/crypki/tls-crt/server.crt
```

### Details
Crypki does not have a docker image in a public registry. Therefore, [this fork](https://github.com/denniskniep/crypki) is hosting the image on ghcr.io


## Development, Testing & Debugging

Build Keycloak Extension
```
mvn clean install
```

Start environment with docker-compose
```
sudo docker-compose -f docker-compose.debug.yaml up --build
```

Connect to debug port (i.e. with IntelliJ)
```
Host: localhost
Port: 8787
Args: -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8787
```



## Crypki

### RestAPI

Get all keys
```
curl -X GET https://localhost:4443/v3/sig/blob/keys
```

Get public key
```
curl -X GET https://localhost:4443/v3/sig/blob/keys/sign-blob-key
```

Sign Digest
```
curl -X POST -H "Content-Type: application/json" https://localhost:4443/v3/sig/blob/keys/sign-blob-key --data '{"digest": "myS064oomwdla8bVuvufU4WNpXmmsDReGstK0frG7K4=", "hash_algorithm": "SHA256"}'
```

### SoftHSM Commands
Docker exec into crypki container

List all slots:
```
pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --pin 123456 -L
```

Test specific slot
```
pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --login --slot 0x70fc6051 --pin 123456 --test
```

List Objects
```
pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --login --slot 0x70fc6051 --pin 123456 --list-objects
```

Read Public Key
```
pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --login --slot 0x70fc6051 --pin 123456 --read-object --type pubkey --label sign_blob | base64
```

Supported Mechanisms
```
pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --login --slot 0x70fc6051 --pin 123456 --label sign_blob -M
```

Signing
```
echo -n '' | base64 --decode > data
cat data | pkcs11-tool --module "/usr/lib/softhsm/libsofthsm2.so" --login --slot 0x70fc6051 --pin 123456 --label sign_blob --sign --mechanism RSA-PKCS > data.sig
```
