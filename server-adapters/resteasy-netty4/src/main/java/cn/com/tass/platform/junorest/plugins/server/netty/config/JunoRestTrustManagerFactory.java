package cn.com.tass.platform.junorest.plugins.server.netty.config;

import io.netty.handler.ssl.util.SimpleTrustManagerFactory;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * Created by panzhuowen on 2020/1/10.
 */
public class JunoRestTrustManagerFactory extends SimpleTrustManagerFactory {


    private final X509Certificate[] caCertificates;

    private final X509Certificate[] clientCertificates;

    public JunoRestTrustManagerFactory(final X509Certificate[] caCertificates, final X509Certificate[] clientCertificates) {
        this.caCertificates = caCertificates;
        this.clientCertificates = clientCertificates;
    }

    private final TrustManager tm = new X509TrustManager() {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String s) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return caCertificates;
        }
    };

    @Override
    protected void engineInit(KeyStore keyStore) throws Exception {

    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {

    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[] {tm};
    }
}
