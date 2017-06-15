/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.http.server;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.httpserver.v1.FileOrValueType;
import org.xipki.httpserver.v1.HttpserverType;
import org.xipki.httpserver.v1.KeystoreType;
import org.xipki.httpserver.v1.TlsType;
import org.xipki.httpserver.v1.TruststoreType;
import org.xipki.password.PasswordResolver;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public final class HttpServers {

    private static final Logger LOG = LoggerFactory.getLogger(HttpServers.class);

    private final Set<HttpServer> servers = new HashSet<>();

    private ServletListener servletListener;

    private HttpServersConf conf;

    private PasswordResolver passwordResolver;

    public void setServletListener(ServletListener servletListener) {
        this.servletListener = servletListener;
        for (HttpServer server : servers) {
            server.setServletListener(servletListener);
        }
    }

    public void setPasswordResolver(PasswordResolver passwordResolver) {
        this.passwordResolver = passwordResolver;
    }

    public void setConf(HttpServersConf conf) {
        this.conf = conf;
    }

    public void start() throws Exception {
        if (conf == null) {
            throw new IllegalStateException("conf is not set");
        }

        if (servletListener == null) {
            throw new IllegalStateException("servletListener is not set");
        }

        List<HttpserverType> serverConfs = conf.getConf().getHttpserver();
        Set<Integer> ports = new HashSet<>();
        for (HttpserverType conf : serverConfs) {
            if (!conf.isEnabled()) {
                LOG.info("HTTP server on port {} is disabled, ignore it", conf.getPort());
            }

            int port = conf.getPort();
            if (ports.contains(port)) {
                throw new Exception("Duplicated use of the port " + port);
            }
            ports.add(port);
            int numThreads = (conf.getThreads() == null) ? 0 : conf.getThreads().intValue();

            String str = conf.getReverseProxy();
            SslReverseProxyMode mode;
            if (str == null || str.equalsIgnoreCase("NONE")) {
                mode = SslReverseProxyMode.NONE;
            } else if (str.equalsIgnoreCase("APACHE")) {
                mode = SslReverseProxyMode.APACHE;
            } else {
                throw new Exception("invalid reverseProxy " + str);
            }

            HttpServer server = new HttpServer(buildSslContext(conf), port, numThreads);
            server.setServletListener(servletListener);
            server.setSslReverseProxyMode(mode);
            servers.add(server);
        }

        for (HttpServer server : servers) {
            server.start();
        }
    }

    public void shutdown() {
        if (servers.isEmpty()) {
            LOG.info("found no HTTP server to shutdown");
            return;
        }

        for (HttpServer server : servers) {
            server.shutdown();
            LOG.info("shutdown HTTP server {}", server);
        }

        servers.clear();
    }

    private SslContext buildSslContext(HttpserverType conf)
            throws Exception {
        TlsType tt = conf.getTls();
        if (tt == null) {
            return null;
        }

        KeystoreType kst = tt.getKeystore();
        SslContextBuilder builder;
        // key and certificate
        if (kst == null) {
            throw new IllegalArgumentException("no keystore is configured");
        } else {
            char[] kstPwd = passwordResolver.resolvePassword(kst.getPassword());
            KeyStore ks = loadKeyStore(kst.getType(), kst.getStore(), kstPwd);
            String alias = kst.getKeyAlias();
            if (alias != null) {
                if (!ks.isKeyEntry(alias)) {
                    throw new Exception("'" + alias + "' is not a valid key alias");
                }
            } else {
                Enumeration<String> aliases = ks.aliases();
                while(aliases.hasMoreElements()) {
                    String al = aliases.nextElement();
                    if (ks.isKeyEntry(al)) {
                        alias = al;
                        break;
                    }
                }

                if (alias == null) {
                    throw new Exception("found no key entries in the keystore");
                }
            }

            char[] keypwd = (kst.getKeyPassword() == null)
                    ? kstPwd : passwordResolver.resolvePassword(kst.getKeyPassword());
            PrivateKey key = (PrivateKey) ks.getKey(alias, keypwd);
            Certificate[] certs = ks.getCertificateChain(alias);
            X509Certificate[] keyCertChain = new X509Certificate[certs.length];
            for (int i = 0; i < certs.length; i++) {
                keyCertChain[i] = (X509Certificate) certs[i];
            }
            builder = SslContextBuilder.forServer(key, keyCertChain);
        }

        boolean opensslAvailable = OpenSsl.isAvailable();

        // providers
        SslProvider sslProvider;
        if (tt.getProvider() == null) {
            if (!opensslAvailable) {
                logOpenSslWarning();
            }
            sslProvider = SslContext.defaultServerProvider();
        } else {
            String providerStr = tt.getProvider();
            String providerStr0 = providerStr.toLowerCase().replaceAll("[^a-z0-9]+", "");
            if ("jdk".equals(providerStr0)) {
                sslProvider = SslProvider.JDK;
            } else if ("openssl".equals(providerStr0) || "opensslrefcnt".equals(providerStr0)) {
                if (!opensslAvailable) {
                    logOpenSslWarning();
                    throw new Exception("OpenSSL not available");
                }

                sslProvider = "openssl".equals(providerStr0)
                        ? SslProvider.OPENSSL : SslProvider.OPENSSL_REFCNT;
            } else {
                throw new Exception("unknwon SSL provider " + providerStr);
            }
        }
        LOG.info("use SSL provider {}", sslProvider);
        builder.sslProvider(sslProvider);

        List<String> availableProtocols;
        List<String> availableCiphersuits;
        switch (sslProvider) {
            case JDK:
                SSLParameters sslParams = SSLContext.getDefault().getSupportedSSLParameters();
                availableProtocols = Arrays.asList(sslParams.getProtocols());
                availableCiphersuits = Arrays.asList(sslParams.getCipherSuites());
                break;
            case OPENSSL:
            case OPENSSL_REFCNT:
                // any way to get the supported protocols of OpenSSL?
                availableProtocols = Arrays.asList("TLSv1.1", "TLSv1.2");
                availableCiphersuits = new ArrayList<>(OpenSsl.availableJavaCipherSuites());
                break;
            default:
                throw new RuntimeException(
                        "should not reach here, unknown SssProvider " + sslProvider);
        }

        // protocols
        List<String> protocols;
        if (tt.getProtocols() != null) {
            protocols = tt.getProtocols().getProtocol();
        } else {
            protocols = Arrays.asList("TLSv1.1", "TLSv1.2");
        }

        final String[] strArray = new String[0];
        Set<String> usedProtocols = new HashSet<>();
        for (String protocol : protocols) {
            boolean added = false;
            for (String supported : availableProtocols) {
                if (protocol.equalsIgnoreCase(supported)) {
                    usedProtocols.add(supported);
                    added = true;
                    break;
                }
            }

            if (!added) {
                LOG.warn("SSL Protocol {} unsupported, ignore it", protocol);
            }
        }

        if (usedProtocols.isEmpty()) {
            throw new Exception("None of the configured SSL protocols is supported");
        }

        LOG.info("use SSL protocols {}", usedProtocols);
        builder.protocols(usedProtocols.toArray(strArray));

        // canonicalize the cipher suites
        boolean cipherWithTLS = availableCiphersuits.get(0).startsWith("TLS_");

        // cipher suites
        Set<String> usedCipherSuites = new HashSet<>();
        if (tt.getCiphersuites() != null) {
            for (String cipherSuite : tt.getCiphersuites().getCiphersuite()) {
                if (cipherSuite.length() < 5) {
                    LOG.warn("cipher suite {} unsupported, ignore it", cipherSuite);
                    continue;
                }

                String adaptedCipher;
                if (cipherWithTLS == cipherSuite.startsWith("TLS_")) {
                    adaptedCipher = cipherSuite;
                } else {
                    if (cipherWithTLS) {
                        adaptedCipher  = "TLS_" + cipherSuite.substring(4);
                    } else {
                        adaptedCipher = "SSL_" + cipherSuite.substring(4);
                    }
                }

                boolean added = false;
                for (String supported : availableCiphersuits) {
                    if (adaptedCipher.equalsIgnoreCase(supported)) {
                        usedCipherSuites.add(supported);
                        added = true;
                        break;
                    }
                }

                if (!added) {
                    LOG.warn("SSL cipher suite {} unsupported, ignore it", cipherSuite);
                }
            }
        } else {
            String[] excludeMiddlePatterns = {"_3DES", "_DES", "EMPTY", "EXPORT", "anno", "NULL"};
            String[] excludeEndPatterns = {"MD5", "SHA"};

            for (String cipherSuite : availableCiphersuits) {
                boolean add = true;
                for (String p : excludeMiddlePatterns) {
                    if (cipherSuite.contains(p)) {
                        add = false;
                        break;
                    }
                }

                if (add) {
                    for (String p : excludeEndPatterns) {
                        if (cipherSuite.endsWith(p)) {
                            add = false;
                            break;
                        }
                    }
                }

                if (add) {
                    usedCipherSuites.add(cipherSuite);
                }
            }
        }

        LOG.info("use SSL cipher suites {}", usedCipherSuites);
        builder.ciphers(usedCipherSuites);

        // client authentication
        ClientAuth clientAuth;
        String str = tt.getClientauth();
        if ("none".equalsIgnoreCase(str)) {
            clientAuth = ClientAuth.NONE;
        } else if ("optional".equalsIgnoreCase(str)) {
            clientAuth = ClientAuth.OPTIONAL;
        } else if ("require".equalsIgnoreCase(str)) {
            clientAuth = ClientAuth.REQUIRE;
        } else {
            throw new Exception("invalid client authentication '" + str + "'");
        }
        builder.clientAuth(clientAuth);

        if (clientAuth != ClientAuth.NONE) {
            TruststoreType tst = tt.getTruststore();
            if (tst == null) {
                throw new Exception(
                        "Client authentication is activated, but no truststore is configured");
            }

            char[] pwd = passwordResolver.resolvePassword(tst.getPassword());
            KeyStore ks = loadKeyStore(tst.getType(), tst.getStore(), pwd);
            List<X509Certificate> trustcerts = new LinkedList<>();
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                trustcerts.add((X509Certificate) cert);
            }

            builder.trustManager(trustcerts.toArray(new X509Certificate[0]));
        }

        return builder.build();
    }

    private KeyStore loadKeyStore(String storeType, FileOrValueType store, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
             {
        InputStream stream;
        if (store.getValue() != null) {
            stream = new ByteArrayInputStream(store.getValue());
        } else {
            stream = new FileInputStream(store.getFile());
        }

        KeyStore keystore = KeyStore.getInstance(storeType);
        try {
            keystore.load(stream, password);
        } finally {
            stream.close();
        }
        return keystore;
    }

    private static void logOpenSslWarning() {
        if (LOG.isWarnEnabled()) {
            StringBuilder sb = new StringBuilder(120);
            sb.append("To use the OpenSSL as SSL provider, both libapr-1 and OpenSSL must be ")
                .append("installed and configured. Note that OpenSSL cannot be applied in ")
                .append("Fedora distribution");
            LOG.warn(sb.toString());
        }
    }

}
