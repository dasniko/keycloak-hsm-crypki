package de.denniskniep.keycloak.hsm.crypki.service;

public class MutualTlsConfig {

    private String clientCaPath;
    private String clientCertPath;
    private String clientKeyPath;
    private String serverCertPath;

    public String getClientCaPath() {
        return clientCaPath;
    }

    public void setClientCaPath(String clientCaPath) {
        this.clientCaPath = clientCaPath;
    }

    public String getClientCertPath() {
        return clientCertPath;
    }

    public void setClientCertPath(String clientCertPath) {
        this.clientCertPath = clientCertPath;
    }

    public String getClientKeyPath() {
        return clientKeyPath;
    }

    public void setClientKeyPath(String clientKeyPath) {
        this.clientKeyPath = clientKeyPath;
    }

    public String getServerCertPath() {
        return serverCertPath;
    }

    public void setServerCertPath(String serverCertPath) {
        this.serverCertPath = serverCertPath;
    }
}
