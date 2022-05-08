/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.qa.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.*;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.util.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Speed test of PKCS#12 signature creation.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12SignSpeed extends BenchmarkExecutor {

  public static class AESGmac extends P12SignSpeed {

    public AESGmac(SecurityFactory securityFactory, String signatureAlgorithm,
        int threads)
            throws Exception {
      super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
          "JCEKS AES-GMAC signature creation", threads);
    }

    private static byte[] generateKeystore(String signatureAlgorithm)
        throws Exception {
      int keysize = getKeysize(signatureAlgorithm);
      P12KeyGenerationResult identity = new P12KeyGenerator().generateSecretKey(
          "AES", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
      return identity.keystore();
    }

    public static int getKeysize(String hmacAlgorithm) {
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
      int keysize;
      if ("AES128-GMAC".equals(hmacAlgorithm)) {
        keysize = 128;
      } else if ("AES192-GMAC".equals(hmacAlgorithm)) {
        keysize = 192;
      } else if ("AES256-GMAC".equals(hmacAlgorithm)) {
        keysize = 256;
      } else {
        throw new IllegalArgumentException("unknown GMAC algorithm " + hmacAlgorithm);
      }
      return keysize;
    }

  } // class AESGmac

  public static class DSA extends P12SignSpeed {

    public DSA(SecurityFactory securityFactory, String signatureAlgorithm, int threads,
        int plength, int qlength)
            throws Exception {
      super(securityFactory, signatureAlgorithm,
          generateKeystore(plength, qlength), "PKCS#12 DSA signature creation\nplength: " + plength
              + "\nqlength: " + qlength, threads);
    }

    private static byte[] generateKeystore(int plength, int qlength)
        throws Exception {
      byte[] keystoreBytes = getPrecomputedDSAKeystore(plength, qlength);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(
            PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        P12KeyGenerationResult identity = new P12KeyGenerator().generateDSAKeypair(
            plength, qlength, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class DSA

  public static class EC extends P12SignSpeed {

    public EC(SecurityFactory securityFactory, String signatureAlgorithm, int threads,
        ASN1ObjectIdentifier curveOid)
            throws Exception {
      super(securityFactory, signatureAlgorithm, generateKeystore(curveOid),
          "PKCS#12 EC signature creation\ncurve: " + curveOid.getId(), threads);
    }

    private static byte[] generateKeystore(ASN1ObjectIdentifier curveOid)
        throws Exception {
      byte[] keystoreBytes = getPrecomputedECKeystore(curveOid);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(
            PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        P12KeyGenerationResult identity;
        if (EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)) {
          identity = new P12KeyGenerator().generateEdECKeypair(curveOid, params, null);
        } else {
          identity = new P12KeyGenerator().generateECKeypair(curveOid, params, null);
        }
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class EC

  public static class HMAC extends P12SignSpeed {

    public HMAC(SecurityFactory securityFactory, String signatureAlgorithm, int threads)
        throws Exception {
      super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
          "JCEKS HMAC signature creation", threads);
    }

    private static byte[] generateKeystore(String signatureAlgorithm)
        throws Exception {
      int keysize = getKeysize(signatureAlgorithm);
      P12KeyGenerationResult identity = new P12KeyGenerator().generateSecretKey(
          "GENERIC", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
      return identity.keystore();
    }

    private static int getKeysize(String hmacAlgorithm) {
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
      int keysize;
      if ("HMACSHA1".equals(hmacAlgorithm)) {
        keysize = 160;
      } else if ("HMACSHA224".equals(hmacAlgorithm) || "HMACSHA3-224".equals(hmacAlgorithm)) {
        keysize = 224;
      } else if ("HMACSHA256".equals(hmacAlgorithm) || "HMACSHA3-256".equals(hmacAlgorithm)) {
        keysize = 256;
      } else if ("HMACSHA384".equals(hmacAlgorithm) || "HMACSHA3-384".equals(hmacAlgorithm)) {
        keysize = 384;
      } else if ("HMACSHA512".equals(hmacAlgorithm) || "HMACSHA3-512".equals(hmacAlgorithm)) {
        keysize = 512;
      } else {
        throw new IllegalArgumentException("unknown HMAC algorithm " + hmacAlgorithm);
      }
      return keysize;
    }

  } // class HMAC

  public static class RSA extends P12SignSpeed {

    public RSA(SecurityFactory securityFactory, String signatureAlgorithm, int threads,
        int keysize, BigInteger publicExponent)
            throws Exception {
      super(securityFactory, signatureAlgorithm, generateKeystore(keysize, publicExponent),
          "PKCS#12 RSA signature creation\nkeysize: " + keysize
              + "\npublic exponent: " + publicExponent, threads);
    }

    private static byte[] generateKeystore(int keysize, BigInteger publicExponent)
        throws Exception {
      byte[] keystoreBytes = getPrecomputedRSAKeystore(keysize, publicExponent);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(
            PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        P12KeyGenerationResult identity = new P12KeyGenerator().generateRSAKeypair(
            keysize, publicExponent, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class RSA

  public static class SM2 extends P12SignSpeed {

    public SM2(SecurityFactory securityFactory, int threads)
        throws Exception {
      super(securityFactory, "SM3WITHSM2", generateKeystore(GMObjectIdentifiers.sm2p256v1),
          "PKCS#12 SM2 signature creation", threads);
    }

    private static byte[] generateKeystore(ASN1ObjectIdentifier curveNOid)
        throws Exception {
      byte[] keystoreBytes = getPrecomputedECKeystore(curveNOid);
      if (keystoreBytes == null) {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(
            PASSWORD.toCharArray());
        params.setRandom(new SecureRandom());
        P12KeyGenerationResult identity = new P12KeyGenerator().generateECKeypair(
            curveNOid, params, null);
        keystoreBytes = identity.keystore();
      }
      return keystoreBytes;
    }

  } // class SM2

  class Testor implements Runnable {

    private static final int batch = 16;

    private final byte[][] data = new byte[batch][16];

    public Testor() {
      for (int i = 0; i < data.length; i++) {
        data[i] = RandomUtil.nextBytes(data[i].length);
      }
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          signer.sign(data);
          account(batch, 0);
        } catch (Exception ex) {
          LOG.error("P12SignSpeed.Testor.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Testor

  protected static final String PASSWORD = "1234";

  private static Logger LOG = LoggerFactory.getLogger(P12SignSpeed.class);

  private final ConcurrentContentSigner signer;

  public P12SignSpeed(SecurityFactory securityFactory, String signatureAlgorithm,
      byte[] keystore, String description, int threads)
          throws Exception {
    this("PKCS12", securityFactory, signatureAlgorithm, keystore, description, threads);
  }

  public P12SignSpeed(String tokenType, SecurityFactory securityFactory,
      String signatureAlgorithm, byte[] keystore, String description, int threads)
          throws Exception {
    super(description);

    notNull(securityFactory, "securityFactory");
    notBlank(signatureAlgorithm, "signatureAlgorithm");
    notNull(keystore, "keystore");

    SignerConf signerConf = getKeystoreSignerConf(new ByteArrayInputStream(keystore), PASSWORD,
        signatureAlgorithm, threads + Math.max(2, threads * 5 / 4));
    this.signer = securityFactory.createSigner(tokenType, signerConf, (X509Cert) null);
  }

  @Override
  protected Runnable getTestor()
      throws Exception {
    return new Testor();
  }

  protected static byte[] getPrecomputedRSAKeystore(int keysize, BigInteger publicExponent)
      throws IOException {
    return getPrecomputedKeystore("rsa-" + keysize + "-0x" + publicExponent.toString(16)
      + ".p12");
  }

  protected static byte[] getPrecomputedDSAKeystore(int plength, int qlength)
      throws IOException {
    return getPrecomputedKeystore("dsa-" + plength + "-" + qlength + ".p12");
  }

  protected static byte[] getPrecomputedECKeystore(ASN1ObjectIdentifier curveOid)
      throws IOException {
    return getPrecomputedKeystore("ec-" + curveOid.getId() + ".p12");
  }

  private static byte[] getPrecomputedKeystore(String filename)
      throws IOException {
    InputStream in = P12SignSpeed.class.getResourceAsStream("/testkeys/" + filename);
    return (in == null) ? null : IoUtil.read(in);
  }

  private static SignerConf getKeystoreSignerConf(InputStream keystoreStream,
      String password, String signatureAlgorithm, int parallelism)
          throws IOException {
    ConfPairs conf = new ConfPairs("password", password);
    conf.putPair("algo", signatureAlgorithm);
    conf.putPair("parallelism", Integer.toString(parallelism));
    conf.putPair("keystore", "base64:" + Base64.encodeToString(IoUtil.read(keystoreStream)));
    return new SignerConf(conf.getEncoded());
  }
}
