package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.crypki.service.CrypkeyService;
import de.denniskniep.keycloak.hsm.crypki.service.MutualTlsConfig;
import de.denniskniep.keycloak.hsm.keyprovider.AlgorithmUtils;
import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyProvider;
import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyWrapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.stream.Stream;

public class CrypkiHsmKeyProvider extends HsmKeyProvider {

    private final KeyStatus status;
    private final ComponentModel model;
    private final String url;
    private final String kid;
    private final long providerPriority;
    private final KeyUse use;
    private final String algorithm;
    private final CrypkiHsmKeyWrapper key;
    private final String name;
    private final MutualTlsConfig mutualTlsConfig;


    public CrypkiHsmKeyProvider(ComponentModel model) {
        this.model = model;
        this.kid = model.get(Attributes.KID_KEY);
        this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
        this.providerPriority = model.get(Attributes.PRIORITY_KEY, 0l);
        this.use = Arrays.stream(KeyUse.values())
                .filter(k -> StringUtils.equals(k.getSpecName(), model.get(Attributes.KEY_USE)))
                .findFirst()
                .orElse(null);
        this.algorithm = model.get(CrypkiHsmKeyProviderFactory.ALGORITHM_KEY);
        this.url = model.get(CrypkiHsmKeyProviderFactory.URL_KEY);
        this.name = model.get(CrypkiHsmKeyProviderFactory.NAME_KEY);

        this.mutualTlsConfig = new MutualTlsConfig();
        this.mutualTlsConfig.setClientCaPath(model.get(CrypkiHsmKeyProviderFactory.CLIENT_CA_PATH_KEY));
        this.mutualTlsConfig.setClientCertPath(model.get(CrypkiHsmKeyProviderFactory.CLIENT_CRT_PATH_KEY));
        this.mutualTlsConfig.setClientKeyPath(model.get(CrypkiHsmKeyProviderFactory.CLIENT_KEY_PATH_KEY));
        this.mutualTlsConfig.setServerCertPath(model.get(CrypkiHsmKeyProviderFactory.SERVER_CRT_PATH_KEY));

        if (model.hasNote(KeyWrapper.class.getName())) {
            key = model.getNote(CrypkiHsmKeyWrapper.class.getName());
        } else {
            key = createKeyWrapper();
            model.setNote(CrypkiHsmKeyWrapper.class.getName(), key);
        }
    }

    private CrypkiHsmKeyWrapper createKeyWrapper(){
        CrypkiHsmKeyWrapper key = new CrypkiHsmKeyWrapper();
        key.setProviderId(model.getId());
        key.setProviderPriority(this.providerPriority);
        key.setKid(kid);
        key.setUse(use == null ? KeyUse.SIG : use);
        key.setType(AlgorithmUtils.getTypeByAlgorithm(algorithm));
        key.setAlgorithm(algorithm);
        key.setStatus(status);
        key.setUrl(url);
        key.setName(name);
        key.setMutualTlsConfig(mutualTlsConfig);
        key.setPublicKey(readPublicKey());
        return key;
    }

    private RSAPublicKey readPublicKey()  {
        String pemPublicKey = null;
        try (CrypkeyService crypkeyService = new CrypkeyService(url, mutualTlsConfig)) {
            pemPublicKey = crypkeyService.getPublicKey(name);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String purePublicKeyAsBase64 = pemPublicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(purePublicKeyAsBase64);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Stream<HsmKeyWrapper> getHsmKeysStream() {
        return Stream.of(key);
    }
}
