package de.denniskniep.keycloak.hsm.crypki.service;

import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

import java.io.Closeable;
import java.io.IOException;
import java.util.Base64;

public class CrypkeyService {

    private final KeycloakSession session;
    private final String baseUrl;

    public CrypkeyService(KeycloakSession session, String baseUrl)  {
        this.session = session;
        this.baseUrl = baseUrl;
    }

    public String getPublicKey(String keyName) throws IOException {
        BlobKeyResponse blobKey = SimpleHttp.doGet(baseUrl + "/v3/sig/blob/keys/" + keyName, session).acceptJson().asJson(BlobKeyResponse.class);
        return blobKey.getKey();
    }

    public String getX509Certificate() throws IOException {
        BlobCertResponse cert = SimpleHttp.doGet(baseUrl  + "/v3/sig/x509-cert/keys/x509-key", session).acceptJson().asJson(BlobCertResponse.class);
        return cert.getCert();
    }

    public  byte[] sign(String keyName, String hashAlgorithm, byte[] bytes) throws IOException {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        BlobKeySigningRequest request = new BlobKeySigningRequest();
        request.setDigest(new String(encoded));
        request.setHashAlgorithm(convertHashAlgorithmFromJavaToPKCS11(hashAlgorithm));

        BlobKeySigningResponse blobKey = SimpleHttp.doPost(baseUrl + "/v3/sig/blob/keys/" + keyName, session).json(request).asJson(BlobKeySigningResponse.class);
        String signature = blobKey.getSignature();

        return Base64.getDecoder().decode(signature);
    }

    private String convertHashAlgorithmFromJavaToPKCS11(String hashAlgorithm){
        return hashAlgorithm.replace("-", "");
    }

}
