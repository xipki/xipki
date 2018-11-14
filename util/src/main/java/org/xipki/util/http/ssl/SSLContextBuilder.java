// #THIRDPARTY# Apache HttpComponents httpcore v4.4.10 / org.apache.http.ssl
// CHECKSTYLE:OFF

/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.xipki.util.http.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.xipki.util.Args;

/**
 * Builder for {@link javax.net.ssl.SSLContext} instances.
 * <p>
 * Please note: the default Oracle JSSE implementation of {@link SSLContext#init(KeyManager[], TrustManager[], SecureRandom)}
 * accepts multiple key and trust managers, however only first matching type is ever used.
 * See for example:
 * <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html#init%28javax.net.ssl.KeyManager[],%20javax.net.ssl.TrustManager[],%20java.security.SecureRandom%29">
 * SSLContext.html#init
 * </a>
 * <p>
 * TODO Specify which Oracle JSSE versions the above has been verified.
 *  </p>
 * @since 4.4
 */
public class SSLContextBuilder {

  static final String TLS   = "TLS";

  private String protocol;
  private final Set<KeyManager> keyManagers;
  private String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
  private String keyStoreType = KeyStore.getDefaultType();
  private final Set<TrustManager> trustManagers;
  private String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
  private SecureRandom secureRandom;
  private Provider provider;

  public static SSLContextBuilder create() {
    return new SSLContextBuilder();
  }

  public SSLContextBuilder() {
    super();
    this.keyManagers = new LinkedHashSet<KeyManager>();
    this.trustManagers = new LinkedHashSet<TrustManager>();
  }

  /**
   * Sets the SSLContext protocol algorithm name.
   *
   * @param protocol
   *            the SSLContext protocol algorithm name of the requested protocol. See
   *            the SSLContext section in the <a href=
   *            "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
   *            Cryptography Architecture Standard Algorithm Name
   *            Documentation</a> for more information.
   * @return this builder
   * @see <a href=
   *      "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
   *      Cryptography Architecture Standard Algorithm Name Documentation</a>
   * @since 4.4.7
   */
  public SSLContextBuilder setProtocol(final String protocol) {
    this.protocol = protocol;
    return this;
  }

  public SSLContextBuilder setSecureRandom(final SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
    return this;
  }

  public SSLContextBuilder setProvider(final Provider provider) {
    this.provider = provider;
    return this;
  }

  public SSLContextBuilder setProvider(final String name) {
    if (name != null && !name.trim().isEmpty()) {
      this.provider = Security.getProvider(name);
    }
    return this;
  }

  /**
   * Sets the key store type.
   *
   * @param keyStoreType
   *            the SSLkey store type. See
   *            the KeyStore section in the <a href=
   *            "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">Java
   *            Cryptography Architecture Standard Algorithm Name
   *            Documentation</a> for more information.
   * @return this builder
   * @see <a href=
   *      "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">Java
   *      Cryptography Architecture Standard Algorithm Name Documentation</a>
   * @since 4.4.7
   */
  public SSLContextBuilder setKeyStoreType(final String keyStoreType) {
    this.keyStoreType = keyStoreType;
    return this;
  }

  /**
   * Sets the key manager factory algorithm name.
   *
   * @param keyManagerFactoryAlgorithm
   *            the key manager factory algorithm name of the requested protocol. See
   *            the KeyManagerFactory section in the <a href=
   *            "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory">Java
   *            Cryptography Architecture Standard Algorithm Name
   *            Documentation</a> for more information.
   * @return this builder
   * @see <a href=
   *      "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory">Java
   *      Cryptography Architecture Standard Algorithm Name Documentation</a>
   * @since 4.4.7
   */
  public SSLContextBuilder setKeyManagerFactoryAlgorithm(final String keyManagerFactoryAlgorithm) {
    this.keyManagerFactoryAlgorithm = keyManagerFactoryAlgorithm;
    return this;
  }

  /**
   * Sets the trust manager factory algorithm name.
   *
   * @param trustManagerFactoryAlgorithm
   *            the trust manager algorithm name of the requested protocol. See
   *            the TrustManagerFactory section in the <a href=
   *            "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TrustManagerFactory">Java
   *            Cryptography Architecture Standard Algorithm Name
   *            Documentation</a> for more information.
   * @return this builder
   * @see <a href=
   *      "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TrustManagerFactory">Java
   *      Cryptography Architecture Standard Algorithm Name Documentation</a>
   * @since 4.4.7
   */
  public SSLContextBuilder setTrustManagerFactoryAlgorithm(final String trustManagerFactoryAlgorithm) {
    this.trustManagerFactoryAlgorithm = trustManagerFactoryAlgorithm;
    return this;
  }

  public SSLContextBuilder loadTrustMaterial(
      final KeyStore truststore) throws NoSuchAlgorithmException, KeyStoreException {
    final TrustManagerFactory tmfactory = TrustManagerFactory
            .getInstance(trustManagerFactoryAlgorithm == null ? TrustManagerFactory.getDefaultAlgorithm()
                    : trustManagerFactoryAlgorithm);
    tmfactory.init(truststore);
    final TrustManager[] tms = tmfactory.getTrustManagers();
    if (tms != null) {
      for (final TrustManager tm : tms) {
        this.trustManagers.add(tm);
      }
    }
    return this;
  }

  public SSLContextBuilder loadTrustMaterial()
    throws NoSuchAlgorithmException, KeyStoreException {
    return loadTrustMaterial((KeyStore) null);
  }

  public SSLContextBuilder loadTrustMaterial(
      final File file,
      final char[] storePassword) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
    Args.notNull(file, "Truststore file");
    final KeyStore trustStore = KeyStore.getInstance(keyStoreType);
    final FileInputStream instream = new FileInputStream(file);
    try {
      trustStore.load(instream, storePassword);
    } finally {
      instream.close();
    }
    return loadTrustMaterial(trustStore);
  }

  public SSLContextBuilder loadKeyMaterial(
      final KeyStore keystore,
      final char[] keyPassword)
      throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    final KeyManagerFactory kmfactory = KeyManagerFactory
            .getInstance(keyManagerFactoryAlgorithm == null ? KeyManagerFactory.getDefaultAlgorithm()
                    : keyManagerFactoryAlgorithm);
    kmfactory.init(keystore, keyPassword);
    final KeyManager[] kms = kmfactory.getKeyManagers();
    if (kms != null) {
      for (final KeyManager km : kms) {
        keyManagers.add(km);
      }
    }
    return this;
  }

  public SSLContextBuilder loadKeyMaterial(
      final File file,
      final char[] storePassword,
      final char[] keyPassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
    Args.notNull(file, "Keystore file");
    final KeyStore identityStore = KeyStore.getInstance(keyStoreType);
    final FileInputStream instream = new FileInputStream(file);
    try {
      identityStore.load(instream, storePassword);
    } finally {
      instream.close();
    }
    return loadKeyMaterial(identityStore, keyPassword);
  }

  protected void initSSLContext(
      final SSLContext sslContext,
      final Collection<KeyManager> keyManagers,
      final Collection<TrustManager> trustManagers,
      final SecureRandom secureRandom) throws KeyManagementException {
    sslContext.init(
        !keyManagers.isEmpty() ? keyManagers.toArray(new KeyManager[keyManagers.size()]) : null,
        !trustManagers.isEmpty() ? trustManagers.toArray(new TrustManager[trustManagers.size()]) : null,
        secureRandom);
  }

  public SSLContext build() throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext sslContext;
    final String protocolStr = this.protocol != null ? this.protocol : TLS;
    if (this.provider != null) {
      sslContext = SSLContext.getInstance(protocolStr, this.provider);
    } else {
      sslContext = SSLContext.getInstance(protocolStr);
    }

    initSSLContext(sslContext, keyManagers, trustManagers, secureRandom);
    return sslContext;
  }

  @Override
  public String toString() {
    return "[provider=" + provider + ", protocol=" + protocol + ", keyStoreType=" + keyStoreType
        + ", keyManagerFactoryAlgorithm=" + keyManagerFactoryAlgorithm + ", keyManagers=" + keyManagers
        + ", trustManagerFactoryAlgorithm=" + trustManagerFactoryAlgorithm + ", trustManagers=" + trustManagers
        + ", secureRandom=" + secureRandom + "]";
  }

}
