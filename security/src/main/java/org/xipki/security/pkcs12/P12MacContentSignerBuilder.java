// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.DfltConcurrentSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Builder of PKCS#12 MAC signers.
 *
 * @author Lijun Liao (xipki)
 */
public class P12MacContentSignerBuilder {

  private final SecretKey key;

  public P12MacContentSignerBuilder(SecretKey key) {
    this.key = Args.notNull(key, "key");
  }

  /**
   * Constructor from keystore.
   * The specified stream remains open after this method returns.
   * @param keystoreType the keysstore type.
   * @param keystoreStream the inputstream containing the keystore.
   * @param keyPassword the password to read the keystore.
   * @param keyname alias of the key in the keystore.
   * @param keystorePassword password to read the key.
   * @throws XiSecurityException if security error occurs.
   */
  public P12MacContentSignerBuilder(
      String keystoreType, InputStream keystoreStream,
      char[] keystorePassword, String keyname, char[] keyPassword)
      throws XiSecurityException {
    if (!"JCEKS".equalsIgnoreCase(keystoreType)) {
      throw new IllegalArgumentException(
          "unsupported keystore type: " + keystoreType);
    }

    Args.notNull(keystoreStream, "keystoreStream");
    Args.notNull(keystorePassword, "keystorePassword");
    Args.notNull(keyPassword, "keyPassword");

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
    } catch (GeneralSecurityException | IOException | ClassCastException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // constructor

  public ConcurrentSigner createSigner(SignAlgo sigAlgo, int parallelism)
      throws XiSecurityException {
    Args.notNull(sigAlgo, "sigAlgo");
    List<Signer> signers = new ArrayList<>(
        Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      Signer signer = sigAlgo.isGmac()
          ? new AESGmacContentSigner(sigAlgo, key)
          : new HmacSigner(sigAlgo, key);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(
        HashAlgo.SHA1.hash(key.getEncoded()));

    return concurrentSigner;
  } // method createSigner

  public SecretKey getKey() {
    return key;
  }

}
