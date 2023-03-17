// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.xipki.security.*;
import org.xipki.security.util.KeyUtil;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Builder of PKCS#12 MAC signers.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class P12MacContentSignerBuilder {

  private final SecretKey key;

  public P12MacContentSignerBuilder(SecretKey key) {
    this.key = notNull(key, "key");
  }

  public P12MacContentSignerBuilder(
      String keystoreType, InputStream keystoreStream, char[] keystorePassword, String keyname, char[] keyPassword)
      throws XiSecurityException {
    if (!"JCEKS".equalsIgnoreCase(keystoreType)) {
      throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
    }
    notNull(keystoreStream, "keystoreStream");
    notNull(keystorePassword, "keystorePassword");
    notNull(keyPassword, "keyPassword");

    try {
      KeyStore ks = KeyUtil.getInKeyStore(keystoreType);
      ks.load(keystoreStream, keystorePassword);

      String tmpKeyname = keyname;
      if (tmpKeyname == null) {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (ks.isKeyEntry(alias)) {
            tmpKeyname = alias;
            break;
          }
        }
      } else {
        if (!ks.isKeyEntry(tmpKeyname)) {
          throw new XiSecurityException("unknown key named " + tmpKeyname);
        }
      }

      this.key = (SecretKey) ks.getKey(tmpKeyname, keyPassword);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
             | UnrecoverableKeyException | ClassCastException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // constructor

  public ConcurrentContentSigner createSigner(SignAlgo sigAlgo, int parallelism)
      throws XiSecurityException {
    notNull(sigAlgo, "sigAlgo");
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer = sigAlgo.isGmac()
          ? new AESGmacContentSigner(sigAlgo, key) : new HmacContentSigner(sigAlgo, key);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(HashAlgo.SHA1.hash(key.getEncoded()));

    return concurrentSigner;
  } // method createSigner

  public SecretKey getKey() {
    return key;
  }

}
