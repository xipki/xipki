// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.benchmark.BenchmarkExecutor;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.misc.RandomUtil;

import java.security.SecureRandom;

/**
 * Speed test of PKCS#12 signature creation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public final class P12SignSpeed extends BenchmarkExecutor {

  private class Tester implements Runnable {

    private static final int batch = 16;

    private final byte[][] data = new byte[batch][16];

    public Tester() {
      for (int i = 0; i < data.length; i++) {
        data[i] = RandomUtil.nextBytes(data[i].length);
      }
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          signer.sign(data);
          account(batch, 0);
        } catch (Exception ex) {
          LOG.error("P12SignSpeed.Tester.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Tester

  private static final String PASSWORD = "1234";

  private static final Logger LOG = LoggerFactory.getLogger(P12SignSpeed.class);

  private final ConcurrentContentSigner signer;

  public P12SignSpeed(SecurityFactory securityFactory, SignAlgo signAlgo,
                      KeySpec keySpec, int threads) throws Exception {
    this("PKCS12", securityFactory, signAlgo, keySpec, threads);
  }

  public P12SignSpeed(String tokenType, SecurityFactory securityFactory,
                      SignAlgo signAlgo, KeySpec keySpec, int threads)
      throws Exception {
    super(tokenType + " Sign speed test with signature algorithm "
        + signAlgo.getJceName() + " and keyspec " + keySpec);

    byte[] keystore = generateKeystore(signAlgo, keySpec);
    Args.notNull(securityFactory, "securityFactory");
    SignerConf signerConf = getKeystoreSignerConf(
        Args.notNull(keystore, "keystore"), PASSWORD,
        Args.notNull(signAlgo, "signAlgo"),
        threads + Math.max(2, threads * 5 / 4));
    this.signer = securityFactory.createSigner(tokenType, signerConf,
        (X509Cert) null);
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  private static byte[] generateKeystore(SignAlgo signAlgo, KeySpec keySpec)
      throws Exception {
    KeystoreGenerationParameters params =
        new KeystoreGenerationParameters(PASSWORD.toCharArray());

    Integer keysize = getSymmKeyBitSize(signAlgo);
    if (keysize != null) {
      if (keySpec != null) {
        throw new IllegalArgumentException(
            "keySpec shall not be non-null: " + keySpec);
      }

      // symmetric key
      String keyType;
      switch (signAlgo) {
        case GMAC_AES128:
        case GMAC_AES192:
        case GMAC_AES256:
          keyType = "AES";
          break;
        default:
          keyType = "HMAC";
      }

      KeyStoreWrapper identity =
          KeyUtil.generateSecretKey(keyType, keysize, params);
      return identity.keystore();
    }

    if (keySpec == null) {
      keySpec = getKeySpec(signAlgo);
      if (keySpec == null) {
        throw new IllegalArgumentException(
            "cannot determine keyspec from signAlgo " + signAlgo);
      }
    }

    params.setRandom(new SecureRandom());
    KeyStoreWrapper identity = KeyUtil.generateKeypair3(keySpec, params);
    return identity.keystore();
  }

  private static SignerConf getKeystoreSignerConf(
      byte[] keystoreBytes, String password, SignAlgo signAlgo,
      int parallelism) {
    return new SignerConf()
        .setPassword(password)
        .setAlgo(signAlgo)
        .setParallelism(parallelism)
        .setKeystore("base64:" +
            Base64.getNoPaddingEncoder().encodeToString(keystoreBytes));
  }

  static Integer getSymmKeyBitSize(SignAlgo signAlgo) {
    switch (signAlgo) {
      case GMAC_AES128:
        return 128;
      case GMAC_AES192:
        return 192;
      case GMAC_AES256:
        return 256;
      case HMAC_SHA1:
        return 160;
      case HMAC_SHA224:
      case HMAC_SHA3_224:
        return 224;
      case HMAC_SHA256:
      case HMAC_SHA3_256:
        return 256;
      case HMAC_SHA384:
      case HMAC_SHA3_384:
        return 384;
      case HMAC_SHA512:
      case HMAC_SHA3_512:
        return 512;
      default:
        return null;
    }
  }

  static KeySpec getKeySpec(SignAlgo signAlgo) {
    if (signAlgo.isRSAPSSSigAlgo() || signAlgo.isRSAPkcs1SigAlgo()) {
      return KeySpec.RSA2048;
    } else if (signAlgo == SignAlgo.SM2_SM3) {
      return KeySpec.SM2P256V1;
    } else if (signAlgo.isECDSASigAlgo()) {
      return KeySpec.SECP256R1;
    } else {
      switch (signAlgo) {
        case ED25519:
          return KeySpec.ED25519;
        case ED448:
          return KeySpec.ED448;
        case ML_DSA_44:
          return KeySpec.MLDSA44;
        case ML_DSA_65:
          return KeySpec.MLDSA65;
        case ML_DSA_87:
          return KeySpec.MLDSA87;
        default:
          return null;
      }
    }
  }

}
