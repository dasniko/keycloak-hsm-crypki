package de.denniskniep.keycloak.hsm.crypki.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

import java.io.*;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

public class CrypkeyHttpClient implements Closeable {

    private final CloseableHttpClient httpclient;
    private final String url;

    public CrypkeyHttpClient(String url, MutualTlsConfig mutualTlsConfig) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException, CertificateException, IOException, InvalidKeySpecException {
        this.url = url;
        this.httpclient = createMutualTlsHttpClient(url, mutualTlsConfig);
    }

    private CloseableHttpClient createMutualTlsHttpClient(String url, MutualTlsConfig mutualTlsConfig) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyManagementException, UnrecoverableKeyException {
        final CloseableHttpClient httpclient;
        char[] keystorePassword = UUID.randomUUID().toString().toCharArray();
        KeyStore keystore = createKeystore(keystorePassword);
        X509Certificate[] certificateChain = new X509Certificate[2];
        certificateChain[0] = readCertFromFile(mutualTlsConfig.getClientCertPath());
        certificateChain[1] = readCertFromFile(mutualTlsConfig.getClientCaPath());
        keystore.setKeyEntry("client-auth", readKeyFromFile(mutualTlsConfig.getClientKeyPath()), keystorePassword, certificateChain);

        KeyStore truststore = createKeystore();
        truststore.setCertificateEntry(url, readCertFromFile(mutualTlsConfig.getServerCertPath()));

        httpclient = HttpClients
            .custom()
            .setSSLContext(new SSLContextBuilder()
                    .loadKeyMaterial(keystore, keystorePassword)
                    .loadTrustMaterial(truststore, null)
                    .build())

            // Allow Insecure SSL:
            //.setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
            //.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)

            .build();
        return httpclient;
    }

    private X509Certificate readCertFromFile(String path) throws FileNotFoundException, CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(path);
        return (X509Certificate) fact.generateCertificate(is);
    }

    private RSAPrivateKey readKeyFromFile(String path) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyAsPEM = Files.readString(new File(path).toPath(), Charset.defaultCharset());

        String privateKeyAsBase64 = privateKeyAsPEM
                .replaceAll("-----BEGIN.*?KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replaceAll("-----END.*?KEY-----", "");

        byte[] privateKey = Base64.getDecoder().decode(privateKeyAsBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private KeyStore createKeystore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return createKeystore(null);
    }

    private KeyStore createKeystore(char[] password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        //create new keystore
        ks.load(null, password);
        return ks;
    }

    public <T> T get(String path, Class<T> resultClazz) throws IOException {
        HttpGet httpget = new HttpGet(URI.create(url + path));
        httpget.setHeader("Accept", "application/json");
        return httpclient.execute(httpget, new JsonResponseHandler<>(resultClazz));
    }

    public <T> T post(String path, Object input, Class<T> resultClazz) throws IOException {
        HttpPost httpPost = new HttpPost(URI.create(url + path));
        ObjectMapper om = new ObjectMapper();
        String json = om.writeValueAsString(input);
        HttpEntity entity = new ByteArrayEntity(json.getBytes(StandardCharsets.UTF_8));
        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        return httpclient.execute(httpPost, new JsonResponseHandler<>(resultClazz));
    }

    @Override
    public void close() throws IOException {
        httpclient.close();
    }
}
