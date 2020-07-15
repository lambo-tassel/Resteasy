package cn.com.tass.platform.junorest.plugins.server.netty.config;

/**
 * Created by panzhuowen on 2020/1/8.
 */
public class SSLConfig {

    private boolean clientAuth = false;

    private String protocolKeyStore;

    private String password;

    private TrustCertValidator trustCertValidator;

    public boolean isClientAuth() {
        return clientAuth;
    }

    public void setClientAuth(boolean clientAuth) {
        this.clientAuth = clientAuth;
    }

    public String getProtocolKeyStore() {
        return protocolKeyStore;
    }

    public void setProtocolKeyStore(String protocolKeyStore) {
        this.protocolKeyStore = protocolKeyStore;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public TrustCertValidator getTrustCertValidator() {
        return trustCertValidator;
    }

    public void setTrustCertValidator(TrustCertValidator trustCertValidator) {
        this.trustCertValidator = trustCertValidator;
    }
}
