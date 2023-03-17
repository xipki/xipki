// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Base64;
import org.xipki.util.CompareUtil;
import org.xipki.util.FileOrBinary;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.StringTokenizer;

/**
 * Configuration of SSL context.
 *
 * @author Lijun Liao (xipki)
 */

public class SslContextConf {

  private static final byte[] PEM_PREFIX = StringUtil.toUtf8Bytes("-----BEGIN");

  private boolean useSslConf = true;

  private PasswordResolver passwordResolver;

  private String sslStoreType;

  private FileOrBinary sslKeystore;

  private String sslKeystorePassword;

  private FileOrBinary[] sslTrustanchors;

  private String sslHostnameVerifier;

  private SSLContext sslContext;

  private SSLSocketFactory sslSocketFactory;

  public static SslContextConf ofSslConf(SslConf ssl) {
    SslContextConf sslCc = new SslContextConf();
    sslCc.setSslStoreType(ssl.getStoreType());

    if (ssl.getKeystore() != null) {
      sslCc.setSslKeystore(ssl.getKeystore());
      sslCc.setSslKeystorePassword(ssl.getKeystorePassword());
    }

    if (ssl.getTrustanchors() != null) {
      sslCc.setSslTrustanchors(ssl.getTrustanchors());
    }

    sslCc.setSslHostnameVerifier(ssl.getHostnameVerifier());
    return sslCc;
  }

  public boolean isUseSslConf() {
    return useSslConf;
  }

  public void setUseSslConf(boolean useSslConf) {
    this.useSslConf = useSslConf;
  }

  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

  public String getSslStoreType() {
    return sslStoreType;
  }

  public void setSslStoreType(String sslStoreType) {
    this.sslStoreType = emptyAsNull(sslStoreType);
  }

  public FileOrBinary getSslKeystore() {
    return sslKeystore;
  }

  public void setSslKeystore(String sslKeystore) {
    String storeFile = emptyAsNull(sslKeystore);
    if (storeFile == null) {
      this.sslKeystore = null;
    } else {
      setSslKeystore(FileOrBinary.ofFile(storeFile));
    }
  }

  public void setSslKeystore(FileOrBinary sslKeystore) {
    this.sslKeystore = sslKeystore;
  }

  public String getSslKeystorePassword() {
    return sslKeystorePassword;
  }

  public void setSslKeystorePassword(String sslKeystorePassword) {
    this.sslKeystorePassword = emptyAsNull(sslKeystorePassword);
  }

  public FileOrBinary[] getSslTrustanchors() {
    return sslTrustanchors;
  }

  public void setSslTrustanchors(String sslTrustanchors) {
    sslTrustanchors = emptyAsNull(sslTrustanchors);
    if (sslTrustanchors == null) {
      this.sslTrustanchors = null;
      return;
    }

    StringTokenizer tokens = new StringTokenizer(sslTrustanchors, ",;:");
    FileOrBinary[] fbs = new FileOrBinary[tokens.countTokens()];
    for (int i = 0; i < fbs.length; i++) {
      fbs[i] = FileOrBinary.ofFile(tokens.nextToken());
    }
    setSslTrustanchors(fbs);
  }

  public void setSslTrustanchors(FileOrBinary[] sslTrustanchors) {
    this.sslTrustanchors = sslTrustanchors;
  }

  public String getSslHostnameVerifier() {
    return sslHostnameVerifier;
  }

  public void setSslHostnameVerifier(String sslHostnameVerifier) {
    this.sslHostnameVerifier = emptyAsNull(sslHostnameVerifier);
  }

  public SSLContext getSslContext() throws ObjectCreationException {
    if (!useSslConf) {
      return null;
    }

    if (sslContext == null) {
      SSLContextBuilder builder = new SSLContextBuilder();
      if (sslStoreType != null) {
        builder.setKeyStoreType(sslStoreType);
      }

      try {
        if (sslKeystore != null) {
          char[] password;
          if (sslKeystorePassword == null) {
            password = null;
          } else {
            password = (passwordResolver == null) ? sslKeystorePassword.toCharArray()
                        : passwordResolver.resolvePassword(sslKeystorePassword);
          }
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
              BufferedReader reader = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bytes)));
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
            } else {
              ks.setCertificateEntry("cert-" + (idx++), parseCert(cf, bytes));
            }
          }
          builder.loadTrustMaterial(ks);
        }

        sslContext = builder.build();
      } catch (IOException | UnrecoverableKeyException | NoSuchAlgorithmException
          | KeyStoreException | CertificateException | KeyManagementException | PasswordResolverException ex) {
        throw new ObjectCreationException("could not build SSLContext: " + ex.getMessage(), ex);
      }
    }

    return sslContext;
  } // method getSslContext

  private static Certificate parseCert(CertificateFactory fact, byte[] certBytes)
      throws CertificateException, IOException {
    try (InputStream certIs = new ByteArrayInputStream(certBytes)) {
      return fact.generateCertificate(certIs);
    }
  }

  public SSLSocketFactory getSslSocketFactory() throws ObjectCreationException {
    if (!useSslConf) {
      return null;
    }

    if (sslSocketFactory == null) {
      getSslContext();
      sslSocketFactory = sslContext.getSocketFactory();
    }

    return sslSocketFactory;
  }

  public HostnameVerifier buildHostnameVerifier() throws ObjectCreationException {
    if (!useSslConf) {
      return null;
    }

    return HostnameVerifiers.createHostnameVerifier(sslHostnameVerifier);
  }

  private static String emptyAsNull(String text) {
    if (text == null) {
      return null;
    } else if (text.trim().isEmpty()) {
      return null;
    } else {
      return text;
    }
  }

}
