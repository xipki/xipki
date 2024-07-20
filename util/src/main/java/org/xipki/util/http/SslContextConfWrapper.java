// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.util.FileOrBinary;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.StringTokenizer;

/**
 * Configuration of SSL context.
 *
 * @author Lijun Liao (xipki)
 */

public class SslContextConfWrapper {

  private boolean useSslConf = true;

  private String sslStoreType;

  private FileOrBinary sslKeystore;

  private String sslKeystorePassword;

  private FileOrBinary[] sslTrustanchors;

  private String sslHostnameVerifier;

  private SSLContext sslContext;

  private SSLSocketFactory sslSocketFactory;

  public SslContextConf toSslContextConf() {
    if (!useSslConf) {
      return null;
    }
    return new SslContextConf(sslStoreType, sslKeystore, sslKeystorePassword,
        sslTrustanchors, sslHostnameVerifier);
  }

  public boolean isUseSslConf() {
    return useSslConf;
  }

  public void setUseSslConf(boolean useSslConf) {
    this.useSslConf = useSslConf;
  }

  public void setSslStoreType(String sslStoreType) {
    this.sslStoreType = emptyAsNull(sslStoreType);
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

  public void setSslKeystorePassword(String sslKeystorePassword) {
    this.sslKeystorePassword = emptyAsNull(sslKeystorePassword);
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
    this.sslTrustanchors = fbs;
  }

  public void setSslHostnameVerifier(String sslHostnameVerifier) {
    this.sslHostnameVerifier = emptyAsNull(sslHostnameVerifier);
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
