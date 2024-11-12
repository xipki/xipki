// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.RandomUtil;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Speed test of PKCS#12 signature creation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P12SignSpeed extends BenchmarkExecutor {

  public static class AESGmac extends P12SignSpeed {

    public AESGmac(SecurityFactory securityFactory, String signatureAlgorithm, int threads) throws Exception {
      super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
          "JCEKS AES-GMAC signature creation", threads);
    }

    private static byte[] generateKeystore(String signatureAlgorithm) throws Exception {
      int keysize = getKeysize(signatureAlgorithm);
      KeyStoreWrapper identity = P12KeyGenerator.generateSecretKey(
          "AES", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
      return identity.keystore();
    }

    public static int getKeysize(String hmacAlgorithm) {
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
      int keysize;
      switch (hmacAlgorithm) {
        case "AES128-GMAC":
          keysize = 128;
          break;
        case "AES192-GMAC":
          keysize = 192;
          break;
        case "AES256-GMAC":
          keysize = 256;
          break;
        default:
          throw new IllegalArgumentException("unknown GMAC algorithm " + hmacAlgorithm);
      }
      return keysize;
    }

  } // class AESGmac

  public static class DSA extends P12SignSpeed {

    public DSA(SecurityFactory securityFactory, String signatureAlgorithm, int threads, int plength, int qlength)
        throws Exception {
      super(securityFactory, signatureAlgorithm,
          generateKeystore(plength, qlength), "PKCS#12 DSA signature creation\nplength: " + plength
              + "\nqlength: " + qlength, threads);
    }

    private static byte[] generateKeystore(int plength, int qlength) throws Exception {
      byte[] keystoreBytes = getPrecomputedDSAKeystore(plength, qlength);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        KeyStoreWrapper identity = P12KeyGenerator.generateDSAKeypair(plength, qlength, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class DSA

  public static class EC extends P12SignSpeed {

    public EC(SecurityFactory securityFactory, String signatureAlgorithm, int threads, ASN1ObjectIdentifier curveOid)
        throws Exception {
      super(securityFactory, signatureAlgorithm, generateKeystore(curveOid),
          "PKCS#12 EC signature creation\ncurve: " + AlgorithmUtil.getCurveName(curveOid), threads);
    }

    private static byte[] generateKeystore(ASN1ObjectIdentifier curveOid) throws Exception {
      byte[] keystoreBytes = getPrecomputedECKeystore(curveOid);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        KeyStoreWrapper identity = EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)
            ? P12KeyGenerator.generateEdECKeypair(curveOid, params, null)
            : P12KeyGenerator.generateECKeypair(curveOid, params, null);

        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class EC

  public static class HMAC extends P12SignSpeed {

    public HMAC(SecurityFactory securityFactory, String signatureAlgorithm, int threads) throws Exception {
      super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
          "JCEKS HMAC signature creation", threads);
    }

    private static byte[] generateKeystore(String signatureAlgorithm) throws Exception {
      int keysize = getKeysize(signatureAlgorithm);
      KeyStoreWrapper identity = P12KeyGenerator.generateSecretKey(
          "GENERIC", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
      return identity.keystore();
    }

    private static int getKeysize(String hmacAlgorithm) {
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
      int keysize;
      switch (hmacAlgorithm) {
        case "HMACSHA1":
          keysize = 160;
          break;
        case "HMACSHA224":
        case "HMACSHA3-224":
          keysize = 224;
          break;
        case "HMACSHA256":
        case "HMACSHA3-256":
          keysize = 256;
          break;
        case "HMACSHA384":
        case "HMACSHA3-384":
          keysize = 384;
          break;
        case "HMACSHA512":
        case "HMACSHA3-512":
          keysize = 512;
          break;
        default:
          throw new IllegalArgumentException("unknown HMAC algorithm " + hmacAlgorithm);
      }
      return keysize;
    }

  } // class HMAC

  public static class RSA extends P12SignSpeed {

    public RSA(SecurityFactory securityFactory, String signatureAlgorithm, int threads,
               int keysize, BigInteger publicExponent) throws Exception {
      super(securityFactory, signatureAlgorithm, generateKeystore(keysize, publicExponent),
          "PKCS#12 RSA signature creation\nkeysize: " + keysize
              + "\npublic exponent: " + publicExponent, threads);
    }

    private static byte[] generateKeystore(int keysize, BigInteger publicExponent) throws Exception {
      byte[] keystoreBytes = getPrecomputedRSAKeystore(keysize, publicExponent);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        KeyStoreWrapper identity = P12KeyGenerator.generateRSAKeypair(keysize, publicExponent, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class RSA

  public static class SM2 extends P12SignSpeed {

    public SM2(SecurityFactory securityFactory, int threads) throws Exception {
      super(securityFactory, "SM3WITHSM2", generateKeystore(GMObjectIdentifiers.sm2p256v1),
          "PKCS#12 SM2 signature creation", threads);
    }

    private static byte[] generateKeystore(ASN1ObjectIdentifier curveNOid) throws Exception {
      byte[] keystoreBytes = getPrecomputedECKeystore(curveNOid);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        KeyStoreWrapper identity = P12KeyGenerator.generateECKeypair(curveNOid, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class SM2

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

  protected static final String PASSWORD = "1234";

  private static final Logger LOG = LoggerFactory.getLogger(P12SignSpeed.class);

  private final ConcurrentContentSigner signer;

  public P12SignSpeed(SecurityFactory securityFactory, String signatureAlgorithm,
                      byte[] keystore, String description, int threads) throws Exception {
    this("PKCS12", securityFactory, signatureAlgorithm, keystore, description, threads);
  }

  public P12SignSpeed(String tokenType, SecurityFactory securityFactory, String signatureAlgorithm,
                      byte[] keystore, String description, int threads) throws Exception {
    super(description);

    Args.notNull(securityFactory, "securityFactory");
    SignerConf signerConf = getKeystoreSignerConf(
        Args.notNull(keystore, "keystore"), PASSWORD,
        Args.notBlank(signatureAlgorithm, "signatureAlgorithm"),
        threads + Math.max(2, threads * 5 / 4));
    this.signer = securityFactory.createSigner(tokenType, signerConf, (X509Cert) null);
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  protected static byte[] getPrecomputedRSAKeystore(int keysize, BigInteger publicExponent) throws IOException {
    return getPrecomputedKeystore("rsa-" + keysize + "-0x" + publicExponent.toString(16) + ".p12");
  }

  protected static byte[] getPrecomputedDSAKeystore(int plength, int qlength) throws IOException {
    return getPrecomputedKeystore("dsa-" + plength + "-" + qlength + ".p12");
  }

  protected static byte[] getPrecomputedECKeystore(ASN1ObjectIdentifier curveOid) throws IOException {
    return getPrecomputedKeystore("ec-" + curveOid.getId() + ".p12");
  }

  private static byte[] getPrecomputedKeystore(String filename) throws IOException {
    InputStream in = P12SignSpeed.class.getResourceAsStream("/testkeys/" + filename);
    return (in == null) ? null : IoUtil.readAllBytesAndClose(in);
  }

  private static SignerConf getKeystoreSignerConf(
      byte[] keystoreBytes, String password, String signatureAlgorithm, int parallelism) {
    ConfPairs conf = new ConfPairs("password", password)
        .putPair("algo", signatureAlgorithm)
        .putPair("parallelism", Integer.toString(parallelism))
        .putPair("keystore", "base64:" + Base64.encodeToString(keystoreBytes));
    return new SignerConf(conf);
  }
}
