package cn.com.tass.platform.junorest.plugins.server.netty.config;

import javax.net.ssl.TrustManagerFactory;

/**
 * Created by panzhuowen on 2020/1/8.
 */
public interface TrustCertValidator {

    TrustManagerFactory trustManagerFactory();


}
