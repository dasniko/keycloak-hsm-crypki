package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyWrapper;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.ServerAsymmetricSignatureVerifierContext;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

public class CrypkiHsmKeyWrapper extends HsmKeyWrapper {

    private final KeycloakSession session;

    private String url;
    private String name;

    public CrypkiHsmKeyWrapper(KeycloakSession session) {
        this.session = session;
    }

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

    @Override
    public SignatureSignerContext createSignatureSignerContext() throws SignatureException {
        return new CrypkiHsmSignatureSignerContext(session, this);
    }

    @Override
    public SignatureVerifierContext createSignatureVerifierContext() throws VerificationException {
        return new ServerAsymmetricSignatureVerifierContext(this);
    }
}
