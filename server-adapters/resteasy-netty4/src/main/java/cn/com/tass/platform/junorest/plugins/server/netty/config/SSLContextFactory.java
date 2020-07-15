package cn.com.tass.platform.junorest.plugins.server.netty.config;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import org.jboss.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * Created by panzhuowen on 2020/1/8.
 */
public class SSLContextFactory {

    private static final Logger logger = Logger.getLogger(SSLContextFactory.class);

    private static final String PROTOCOL = "TLSv1.2";

    private static SSLContext SERVER_CONTEXT;

    private static SslContext openSslContext;

    private static SSLContext CLIENT_CONTEXT;

    private static SslContext openSslClientContext;

    public static SSLContext getServerContext(String pkPath, String password) {
        if (SERVER_CONTEXT != null)
            return SERVER_CONTEXT;
        InputStream in = null;

        try {
            // 密钥管理器
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                in = new FileInputStream(pkPath);
                ks.load(in, password.toCharArray());
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, password.toCharArray());
            }
            SERVER_CONTEXT = SSLContext.getInstance(PROTOCOL);
            SERVER_CONTEXT.init(kmf.getKeyManagers(), null, null);

        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
            }

        }
        return SERVER_CONTEXT;
    }

    public static SslContext getOpenSslServerContext(String pkPath, String password) {
        if (openSslContext != null) {
            return openSslContext;
        }
        InputStream in = null;
        try {
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                in = new FileInputStream(pkPath);
                ks.load(in, password.toCharArray());
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, password.toCharArray());
            }
            openSslContext = SslContextBuilder.forServer(kmf)
                    .sslProvider(SslProvider.OPENSSL).build();
            return openSslContext;
        } catch (Exception e) {
            logger.error("SSL init error cause by", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                in = null;
            }

        }
        return null;

    }

    public static SSLContext getClientContext(String pkPath, String passwd) {
        if (CLIENT_CONTEXT != null)
            return CLIENT_CONTEXT;

        InputStream tIN = null;
        try {
            // 信任库
            TrustManagerFactory tf = null;
            if (pkPath != null) {
                // 密钥库KeyStore
                KeyStore tks = KeyStore.getInstance("JKS");
                // 加载客户端证书
                tIN = new FileInputStream(pkPath);
                tks.load(tIN, passwd.toCharArray());
                tf = TrustManagerFactory.getInstance("SunX509");
                // 初始化信任库
                tf.init(tks);
            }

            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL);
            // 设置信任证书
            CLIENT_CONTEXT.init(null,
                    tf == null ? null : tf.getTrustManagers(), null);

        } catch (Exception e) {
            throw new Error("Failed to initialize the client-side SSLContext");
        } finally {
            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
            }
        }

        return CLIENT_CONTEXT;
    }

    public static SslContext getOpenSslClientContext(String pkPath, String passwd) {

        if (openSslClientContext != null) {
            return openSslClientContext;
        }

        InputStream tIN = null;
        try {

            // 信任库
            TrustManagerFactory tf = null;
            if (pkPath != null) {
                // 密钥库KeyStore
                KeyStore tks = KeyStore.getInstance("JKS");
                // 加载客户端证书
                tIN = new FileInputStream(pkPath);
                tks.load(tIN, passwd.toCharArray());
                tf = TrustManagerFactory.getInstance("SunX509");
                // 初始化信任库
                tf.init(tks);
            }

            openSslClientContext = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.OPENSSL).trustManager(tf).build();

            return openSslClientContext;
        } catch (Exception e) {
            logger.error("SSL init error cause by", e);
        } finally {
            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                tIN = null;
            }

        }

        return null;

    }

    public static SSLContext getServerContext(String pkPath, TrustCertValidator trustCertValidator, String passwd) {
        if (SERVER_CONTEXT != null)
            return SERVER_CONTEXT;
        InputStream in = null;
        InputStream tIN = null;

        try {
            // 密钥管理器
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                in = new FileInputStream(pkPath);
                ks.load(in, passwd.toCharArray());

                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, passwd.toCharArray());
            }
            // 信任库

            SERVER_CONTEXT = SSLContext.getInstance(PROTOCOL);

            // 初始化此上下文
            // 参数一：认证的密钥 参数二：对等信任认证 参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            // 单向认证？无需验证客户端证书
            if (trustCertValidator == null) {
                SERVER_CONTEXT.init(kmf.getKeyManagers(), null, null);
            }
            // 双向认证，需要验证客户端证书
            else {
                SERVER_CONTEXT.init(kmf.getKeyManagers(),
                        trustCertValidator.trustManagerFactory().getTrustManagers(), null);
            }

        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext",
                    e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                in = null;
            }

            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                tIN = null;
            }
        }
        return SERVER_CONTEXT;
    }

    public static SslContext getOpenSslServerContext(String pkPath, TrustCertValidator trustCertValidator, String passwd) {
        if (openSslContext != null)
            return openSslContext;

        InputStream in = null;
        InputStream tIN = null;
        try {
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                in = new FileInputStream(pkPath);
                ks.load(in, passwd.toCharArray());
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, passwd.toCharArray());
            }
            openSslContext = SslContextBuilder.forServer(kmf).trustManager(trustCertValidator.trustManagerFactory())
                    .sslProvider(SslProvider.OPENSSL).build();
            return openSslContext;
        } catch (Exception e) {
            logger.error("SSL init error cause by", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                in = null;
            }

            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                tIN = null;
            }
        }

        return null;

    }

    public static SSLContext getClientContext(String pkPath, TrustCertValidator trustCertValidator, String passwd) {
        if (CLIENT_CONTEXT != null)
            return CLIENT_CONTEXT;

        InputStream in = null;
        InputStream tIN = null;
        try {
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                in = new FileInputStream(pkPath);
                ks.load(in, passwd.toCharArray());
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, passwd.toCharArray());
            }



            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL);
            // 初始化此上下文
            CLIENT_CONTEXT.init(kmf.getKeyManagers(), trustCertValidator.trustManagerFactory().getTrustManagers(), null);

        } catch (Exception e) {
            throw new Error("Failed to initialize the client-side SSLContext");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                in = null;
            }

            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                tIN = null;
            }
        }

        return CLIENT_CONTEXT;
    }

    public static SslContext getOpenSslClientContext(String pkPath,
                                                     TrustCertValidator trustCertValidator, String passwd) {

        if (openSslClientContext != null) {
            return openSslClientContext;
        }

        InputStream in = null;
        InputStream tIN = null;
        try {

            // 密钥管理器
            KeyManagerFactory kmf = null;
            if (pkPath != null) {
                // 密钥库KeyStore
                KeyStore ks = KeyStore.getInstance("JKS");
                // 加载服务端证书
                in = new FileInputStream(pkPath);
                // 加载服务端的KeyStore ；sNetty是生成仓库时设置的密码，用于检查密钥库完整性的密码
                ks.load(in, passwd.toCharArray());

                kmf = KeyManagerFactory.getInstance("SunX509");
                // 初始化密钥管理器
                kmf.init(ks, passwd.toCharArray());
            }


            openSslClientContext = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.OPENSSL).keyManager(kmf)
                    .trustManager(trustCertValidator.trustManagerFactory()).build();

            return openSslClientContext;
        } catch (Exception e) {
            logger.error("SSL init error cause by", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                in = null;
            }
            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    logger.error("SSL init error cause by", e);
                }
                tIN = null;
            }

        }

        return null;

    }

    /**
     * Description:
     *
     * @return
     * @see
     */
    public static SSLEngine getSslServerEngine(SSLConfig sslConfig) {

        SSLEngine sslEngine = null;
        if (sslConfig.isClientAuth()) {
            sslEngine = getServerContext(sslConfig.getProtocolKeyStore(), sslConfig.getTrustCertValidator(), sslConfig.getPassword())
                    .createSSLEngine();
        } else {
            sslEngine = getServerContext(sslConfig.getProtocolKeyStore(), sslConfig.getPassword()).createSSLEngine();
        }

        sslEngine.setUseClientMode(false);
        sslEngine.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1",
                "TLSv1.2"});
        // false为单向认证，true为双向认证
        sslEngine.setNeedClientAuth(sslConfig.isClientAuth());
        return sslEngine;
    }

    public static SSLEngine getOpenSslServerEngine(SSLConfig sslConfig, ByteBufAllocator alloc) {

        SSLEngine sslEngine = null;
        if (sslConfig.isClientAuth()) {
            sslEngine = getOpenSslServerContext(sslConfig.getProtocolKeyStore(), sslConfig.getTrustCertValidator(), sslConfig.getPassword()).newEngine(
                    alloc);
        } else {
            sslEngine = getOpenSslServerContext(sslConfig.getProtocolKeyStore(),
                    sslConfig.getPassword()).newEngine(alloc);
        }

        sslEngine.setUseClientMode(false);
        sslEngine.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1",
                "TLSv1.2"});
        // false为单向认证，true为双向认证
        sslEngine.setNeedClientAuth(sslConfig.isClientAuth());
        return sslEngine;
    }

    public static SSLEngine getSslClientEngine(String pkPath, TrustCertValidator trustCertValidator,
                                               String passwd, boolean isNeedClientAuth) {

        SSLEngine sslEngine = null;
        if (isNeedClientAuth) {
            sslEngine = getClientContext(pkPath, trustCertValidator, passwd)
                    .createSSLEngine();
        } else {
            sslEngine = getClientContext(pkPath, passwd).createSSLEngine();

        }
        sslEngine.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1",
                "TLSv1.2"});
        sslEngine.setUseClientMode(true);
        return sslEngine;
    }

    public static SSLEngine getOpenSslClientEngine(String pkPath, TrustCertValidator trustCertValidator, String passwd, ByteBufAllocator alloc, boolean isNeedClientAuth) {

        SSLEngine sslEngine = null;
        if (isNeedClientAuth) {
            sslEngine = getOpenSslClientContext(pkPath, trustCertValidator, passwd)
                    .newEngine(alloc);
        } else {
            sslEngine = getOpenSslClientContext(pkPath, passwd)
                    .newEngine(alloc);
        }
        sslEngine.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1",
                "TLSv1.2"});
        sslEngine.setUseClientMode(true);
        return sslEngine;
    }

    /**
     * Description:
     *
     * @return
     * @see
     */
    public static SslHandler getSslHandler(SSLConfig sslConfig) {

        if (sslConfig != null) {
            return new SslHandler(getSslServerEngine(sslConfig));
        } else {
            return null;
        }
    }

    public static SslHandler getOpenSslHandler(SSLConfig sslConfig, ByteBufAllocator alloc) {

        if (sslConfig != null) {
            return new SslHandler(getOpenSslServerEngine(sslConfig, alloc));
        } else {
            return null;
        }
    }

}
