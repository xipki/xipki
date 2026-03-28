// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.http;

import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.misc.StringUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.Arrays;
import java.util.Set;

/**
 * Ssl Context Conf Wrapper.
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

  public void setSslTrustanchors(Set<String> sslTrustanchors) {
    if (CollectionUtil.isEmpty(sslTrustanchors)) {
      this.sslTrustanchors = null;
      return;
    }

    FileOrBinary[] fbs = new FileOrBinary[sslTrustanchors.size()];
    int index = 0;
    for (String m : sslTrustanchors) {
      if (StringUtil.isNotBlank(m)) {
        fbs[index++] = FileOrBinary.ofFile(m);
      }
    }
    this.sslTrustanchors = index == fbs.length ? fbs : Arrays.copyOf(fbs, index);
  }

  public void setSslHostnameVerifier(String sslHostnameVerifier) {
    this.sslHostnameVerifier = emptyAsNull(sslHostnameVerifier);
  }

  private static String emptyAsNull(String text) {
    return (text == null || text.trim().isEmpty()) ? null : text;
  }

}
