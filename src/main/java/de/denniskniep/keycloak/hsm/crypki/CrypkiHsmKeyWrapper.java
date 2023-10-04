package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.crypki.service.MutualTlsConfig;
import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyWrapper;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.ServerAsymmetricSignatureVerifierContext;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;

public class CrypkiHsmKeyWrapper extends HsmKeyWrapper {

    private String url;
    private String name;
    private MutualTlsConfig mutualTlsConfig;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public MutualTlsConfig getMutualTlsConfig() {
        return mutualTlsConfig;
    }

    public void setMutualTlsConfig(MutualTlsConfig mutualTlsConfig) {
        this.mutualTlsConfig = mutualTlsConfig;
    }

    @Override
    public SignatureSignerContext createSignatureSignerContext() throws SignatureException {
        return new CrypkiHsmSignatureSignerContext(this);
    }

    @Override
    public SignatureVerifierContext createSignatureVerifierContext() throws VerificationException {
        return new ServerAsymmetricSignatureVerifierContext(this);
    }
}
