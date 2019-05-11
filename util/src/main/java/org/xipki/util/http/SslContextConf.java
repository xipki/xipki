/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.util.http;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ObjectCreationException;

/**
 * TODO.
 * @author Lijun Liao
 */

public class SslContextConf {

  private boolean useSslConf = true;

  private String sslStoreType;

  private FileOrBinary sslKeystore;

  private char[] sslKeystorePassword;

  private FileOrBinary sslTruststore;

  private char[] sslTruststorePassword;

  private String sslHostnameVerifier;

  private SSLContext sslContext;

  private SSLSocketFactory sslSocketFactory;

  public boolean isUseSslConf() {
    return useSslConf;
  }

  public void setUseSslConf(boolean useSslConf) {
    this.useSslConf = useSslConf;
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

  public char[] getSslKeystorePassword() {
    return sslKeystorePassword;
  }

  public void setSslKeystorePassword(char[] sslKeystorePassword) {
    this.sslKeystorePassword = sslKeystorePassword;
  }

  public FileOrBinary getSslTruststore() {
    return sslTruststore;
  }

  public void setSslTruststore(String sslTruststore) {
    String storeFile = emptyAsNull(sslTruststore);
    if (storeFile == null) {
      this.sslTruststore = null;
    } else {
      setSslTruststore(FileOrBinary.ofFile(storeFile));
    }
  }

  public void setSslTruststore(FileOrBinary sslTruststore) {
    this.sslTruststore = sslTruststore;
  }

  public char[] getSslTruststorePassword() {
    return sslTruststorePassword;
  }

  public void setSslTruststorePassword(char[] sslTruststorePassword) {
    this.sslTruststorePassword = sslTruststorePassword;
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
          builder.loadKeyMaterial(
              new ByteArrayInputStream(sslKeystore.readContent()),
                sslKeystorePassword, sslKeystorePassword);
        }

        if (sslTruststore != null) {
          builder.loadTrustMaterial(
              new ByteArrayInputStream(sslTruststore.readContent()), sslTruststorePassword);
        }

        sslContext = builder.build();
      } catch (IOException | UnrecoverableKeyException | NoSuchAlgorithmException
          | KeyStoreException | CertificateException | KeyManagementException ex) {
        throw new ObjectCreationException("could not build SSLContext: " + ex.getMessage(), ex);
      }
    }

    return sslContext;
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
