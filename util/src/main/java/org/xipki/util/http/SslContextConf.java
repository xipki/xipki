// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.Base64;
import org.xipki.pkix.util.misc.CompareUtil;
import org.xipki.pkix.util.conf.FileOrBinary;
import org.xipki.pkix.util.misc.StringUtil;
import org.xipki.pkix.util.password.Passwords;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Ssl Context configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class SslContextConf {

  private static final byte[] PEM_PREFIX = StringUtil.toUtf8Bytes("-----BEGIN");

  private final String sslStoreType;

  private final FileOrBinary sslKeystore;

  private final String sslKeystorePassword;

  private final FileOrBinary[] sslTrustanchors;

  private final String sslHostnameVerifier;

  private SSLContext sslContext;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private boolean initialized;

  private boolean initFailed;

  public SslContextConf(FileOrBinary[] sslTrustanchors, String sslHostnameVerifier) {
    this(null, null, null, sslTrustanchors, sslHostnameVerifier);
  }

  public SslContextConf(
      String sslStoreType, FileOrBinary sslKeystore, String sslKeystorePassword,
      FileOrBinary[] sslTrustanchors, String sslHostnameVerifier) {
    this.sslStoreType = sslStoreType;
    this.sslKeystore = sslKeystore;
    this.sslKeystorePassword = sslKeystorePassword;
    this.sslTrustanchors = sslTrustanchors;
    this.sslHostnameVerifier = sslHostnameVerifier;
  }

  public synchronized void init() throws GenerationException {
    if (initialized) {
      if (initFailed) {
        throw new GenerationException("initialization executed before but failed");
      }
      return;
    }

    try {
      this.hostnameVerifier = HostnameVerifiers.createHostnameVerifier(sslHostnameVerifier);

      SslContextBuilder builder = new SslContextBuilder();
      if (sslStoreType != null) {
        builder.setKeyStoreType(sslStoreType);
      }

      if (sslKeystore != null) {
        char[] password = Passwords.resolvePassword(sslKeystorePassword);
        try (InputStream is = new ByteArrayInputStream(sslKeystore.readContent())) {
          builder.loadKeyMaterial(is, password, password);
        }
      }

      if (sslTrustanchors != null && sslTrustanchors.length != 0) {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, "any".toCharArray());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        int idx = 1;
        for (FileOrBinary fb : sslTrustanchors) {
          byte[] bytes = fb.readContent();
          if (CompareUtil.areEqual(bytes, 0, PEM_PREFIX, 0, PEM_PREFIX.length)) {
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(bytes)))) {
              StringBuilder sb = null;
              String line;
              while ((line = reader.readLine()) != null) {
                if (line.equals("-----BEGIN CERTIFICATE-----")) {
                  sb = new StringBuilder(1000);
                } else if (line.equals("-----END CERTIFICATE-----")) {
                  if (sb != null) {
                    byte[] certBytes = Base64.decode(sb.toString());
                    sb = null;
                    ks.setCertificateEntry("cert-" + (idx++), parseCert(cf, certBytes));
                  }
                } else {
                  if (sb != null) {
                    sb.append(line);
                  }
                }
              }
            }
          } else {
            ks.setCertificateEntry("cert-" + (idx++), parseCert(cf, bytes));
          }
        }
        builder.loadTrustMaterial(ks);
      }

      sslContext = builder.build();
      sslSocketFactory = sslContext.getSocketFactory();
    } catch (Throwable th) {
      initFailed = true;
      throw new GenerationException("could not build SSLContext: " + th.getMessage(), th);
    } finally {
      initialized = true;
    }
  }

  private static Certificate parseCert(CertificateFactory fact, byte[] certBytes)
      throws CertificateException, IOException {
    try (InputStream certIs = new ByteArrayInputStream(certBytes)) {
      return fact.generateCertificate(certIs);
    }
  }

  public SSLContext getSslContext() throws GenerationException {
    init();
    return sslContext;
  }

  public SSLSocketFactory getSslSocketFactory() throws GenerationException {
    init();
    return sslSocketFactory;
  }

  public HostnameVerifier getHostnameVerifier() throws GenerationException {
    init();
    return hostnameVerifier;
  }

  public static SslContextConf ofSslConf(SslConf ssl) {
    return new SslContextConf(ssl.storeType(), ssl.keystore(),
        ssl.keystorePassword(), ssl.trustanchors(), ssl.hostnameVerifier());
  }

}
