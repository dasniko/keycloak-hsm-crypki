package de.denniskniep.keycloak.hsm.crypki.service;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BlobKeySigningRequest {

    private String digest;

    @JsonProperty("hash_algorithm")
    private String hashAlgorithm;

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }
}
