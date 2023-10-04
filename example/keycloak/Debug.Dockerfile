FROM quay.io/keycloak/keycloak:22.0.3

# Downloads JAR file from URL and adds it to the providers directory
ADD --chown=keycloak:keycloak https://github.com/denniskniep/keycloak-hsm/releases/download/v1.0.1/keycloak-hsm-1.0.1.jar /opt/keycloak/providers/keycloak-hsm-1.0.1.jar


