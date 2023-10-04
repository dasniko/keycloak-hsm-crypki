package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.crypki.service.CrypkeyService;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;

import java.security.MessageDigest;

public class CrypkiHsmSignatureSignerContext implements SignatureSignerContext {

    private final CrypkiHsmKeyWrapper key;

    public CrypkiHsmSignatureSignerContext(KeyWrapper key) {
        if(!(key instanceof CrypkiHsmKeyWrapper)){
            throw new IllegalArgumentException("key must be of type ExternalKeyWrapper!");
        }
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
        try (CrypkeyService crypkeyService = new CrypkeyService(key.getUrl(), key.getMutualTlsConfig())) {
            MessageDigest md = MessageDigest.getInstance(getHashAlgorithm());
            md.update(bytes);
            byte[] digest = md.digest();
            return crypkeyService.sign(key.getName(), getHashAlgorithm(), digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
