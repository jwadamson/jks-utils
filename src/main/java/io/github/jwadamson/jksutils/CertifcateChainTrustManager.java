package io.github.jwadamson.jksutils;

import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertifcateChainTrustManager implements X509TrustManager {

    private X509TrustManager defaultTrustManager;
    private X509Certificate[] resultChain;

    public CertifcateChainTrustManager(X509TrustManager defaultTrustManager) {
        this.defaultTrustManager = defaultTrustManager;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[]{};
    }

    public void checkServerTrusted(Object chain, Object authType) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
    throws CertificateException {
        throw new UnsupportedOperationException();
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
    throws CertificateException {
        resultChain = chain; // save the chain
        defaultTrustManager.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getResultChain() {
        return resultChain;
    }
}
