package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.crypki.service.CrypkeyService;
import de.denniskniep.keycloak.hsm.keyprovider.AlgorithmUtils;
import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyProvider;
import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyWrapper;
import org.apache.commons.codec.binary.StringUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.stream.Stream;

public class CrypkiHsmKeyProvider extends HsmKeyProvider {

    private final KeycloakSession session;
    private final KeyStatus status;
    private final ComponentModel model;
    private final String url;
    private final String kid;
    private final long providerPriority;
    private final KeyUse use;
    private final String algorithm;
    private final CrypkiHsmKeyWrapper key;
    private final String name;
    private final CrypkeyService crypkeyService;


    public CrypkiHsmKeyProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
        this.kid = model.get(Attributes.KID_KEY);
        this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
        this.providerPriority = model.get(Attributes.PRIORITY_KEY, 0L);
        this.use = Arrays.stream(KeyUse.values())
                .filter(k -> StringUtils.equals(k.getSpecName(), model.get(Attributes.KEY_USE)))
                .findFirst()
                .orElse(null);
        this.algorithm = model.get(CrypkiHsmKeyProviderFactory.ALGORITHM_KEY);
        this.url = model.get(CrypkiHsmKeyProviderFactory.URL_KEY);
        this.name = model.get(CrypkiHsmKeyProviderFactory.NAME_KEY);

        this.crypkeyService = new CrypkeyService(session, url);

        if (model.hasNote(KeyWrapper.class.getName())) {
            key = model.getNote(CrypkiHsmKeyWrapper.class.getName());
        } else {
            key = createKeyWrapper();
            model.setNote(CrypkiHsmKeyWrapper.class.getName(), key);
        }
    }

    private CrypkiHsmKeyWrapper createKeyWrapper(){
        CrypkiHsmKeyWrapper key = new CrypkiHsmKeyWrapper(session);
        key.setProviderId(model.getId());
        key.setProviderPriority(this.providerPriority);
        key.setKid(kid);
        key.setUse(use == null ? KeyUse.SIG : use);
        key.setType(AlgorithmUtils.getTypeByAlgorithm(algorithm));
        key.setAlgorithm(algorithm);
        key.setStatus(status);
        key.setUrl(url);
        key.setName(name);
        key.setPublicKey(readPublicKey());
        key.setCertificate(readCertificate());
        return key;
    }

    private X509Certificate readCertificate() {
        try {
            String certString = crypkeyService.getX509Certificate();
            return PemUtils.decodeCertificate(certString);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private RSAPublicKey readPublicKey()  {
        try {
            String pemPublicKey = crypkeyService.getPublicKey(name);
            return (RSAPublicKey) PemUtils.decodePublicKey(pemPublicKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public Stream<HsmKeyWrapper> getHsmKeysStream() {
        return Stream.of(key);
    }
}
