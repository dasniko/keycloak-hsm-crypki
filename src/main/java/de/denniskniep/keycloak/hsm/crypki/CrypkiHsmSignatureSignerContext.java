package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.crypki.service.CrypkeyService;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.models.KeycloakSession;

import java.security.MessageDigest;

public class CrypkiHsmSignatureSignerContext implements SignatureSignerContext {

    private final KeycloakSession session;
    private final CrypkiHsmKeyWrapper key;

    public CrypkiHsmSignatureSignerContext(KeycloakSession session, KeyWrapper key) {
        if(!(key instanceof CrypkiHsmKeyWrapper)){
            throw new IllegalArgumentException("key must be of type ExternalKeyWrapper!");
        }
        this.session = session;
        this.key = (CrypkiHsmKeyWrapper)key;
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public String getHashAlgorithm() {
        return JavaAlgorithm.getJavaAlgorithmForHash(getAlgorithm());
    }

    @Override
    public byte[] sign(byte[] bytes) throws SignatureException {
        try {
            CrypkeyService crypkeyService = new CrypkeyService(session, key.getUrl());
            MessageDigest md = MessageDigest.getInstance(getHashAlgorithm());
            md.update(bytes);
            byte[] digest = md.digest();
            return crypkeyService.sign(key.getName(), getHashAlgorithm(), digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
