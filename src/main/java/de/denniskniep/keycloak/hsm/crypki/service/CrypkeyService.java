package de.denniskniep.keycloak.hsm.crypki.service;

import java.io.Closeable;
import java.io.IOException;
import java.util.Base64;

public class CrypkeyService implements Closeable {

    private final CrypkeyHttpClient httpClient;


    public CrypkeyService(String url, MutualTlsConfig mutualTlsConfig)  {
        try {
            this.httpClient = new CrypkeyHttpClient(url, mutualTlsConfig);
        } catch (Exception e) {
            throw new RuntimeException("CrypkeyHttpClient can not be created: " + e.getMessage(), e);
        }
    }

    public String getPublicKey(String keyName) throws IOException {
        BlobKeyResponse blobKey = httpClient.get("/v3/sig/blob/keys/" +keyName, BlobKeyResponse.class);
        return blobKey.getKey();
    }

    public String getX509Certificate() throws IOException {
        BlobCertResponse cert = httpClient.get("/v3/sig/x509-cert/keys/x509-key", BlobCertResponse.class);
        return cert.getCert();
    }

    public  byte[] sign(String keyName, String hashAlgorithm, byte[] bytes) throws IOException {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        BlobKeySigningRequest request = new BlobKeySigningRequest();
        request.setDigest(new String(encoded));
        request.setHashAlgorithm(convertHashAlgorithmFromJavaToPKCS11(hashAlgorithm));

        BlobKeySigningResponse blobKey = httpClient.post("/v3/sig/blob/keys/" +keyName, request, BlobKeySigningResponse.class);
        String signature = blobKey.getSignature();

        return Base64.getDecoder().decode(signature);
    }

    private String convertHashAlgorithmFromJavaToPKCS11(String hashAlgorithm){
        return hashAlgorithm.replace("-", "");
    }

    @Override
    public void close() throws IOException {
        httpClient.close();
    }
}
