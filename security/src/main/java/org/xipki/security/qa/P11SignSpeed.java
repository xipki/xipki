// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.*;
import org.xipki.util.exception.ObjectCreationException;

import java.math.BigInteger;
import java.time.Clock;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Speed test of PKCS#11 signature creation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P11SignSpeed extends BenchmarkExecutor {

  public static class DSA extends P11SignSpeed {

    public DSA(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads, int plength, int qlength)
        throws Exception {
      this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads, plength, qlength);
    }

    public DSA(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads, int plength, int qlength)
        throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, plength, qlength),
          "PKCS#11 DSA signature creation\npLength: " + plength + "\nqLength: " + qlength, threads);
    }

    private static PKCS11KeyId generateKey(
        boolean keyPresent, P11Slot slot, byte[] keyId, String keyLabel, int plength, int qlength)
        throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateDSAKeypair(plength, qlength, getNewKeyControl(keyId, keyLabel));
    }

  } // class DSA

  public static class EC extends P11SignSpeed {

    public EC(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads, ASN1ObjectIdentifier curveOid)
        throws Exception {
      this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads, curveOid);
    }

    public EC(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads, ASN1ObjectIdentifier curveOid)
        throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, curveOid),
          "PKCS#11 EC signature creation\ncurve: " + AlgorithmUtil.getCurveName(curveOid), threads);
    }

    private static PKCS11KeyId generateKey(
        boolean keyPresent, P11Slot slot, byte[] keyId, String keyLabel, ASN1ObjectIdentifier curveOid)
        throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      try {
        return slot.generateECKeypair(curveOid, getNewKeyControl(keyId, keyLabel));
      } catch (Exception ex) {
        throw new Exception("error generating EC keypair for curve " + AlgorithmUtil.getCurveName(curveOid), ex);
      }
    }

  } // class EC

  public static class HMAC extends P11SignSpeed {

    public HMAC(SecurityFactory securityFactory, P11Slot slot, byte[] keyId, String signatureAlgorithm, int threads)
        throws Exception {
      this(true, securityFactory, slot, keyId, null, signatureAlgorithm, threads);
    }

    public HMAC(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads)
        throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, signatureAlgorithm),
          "PKCS#11 HMAC signature creation", threads);
    }

    private static PKCS11KeyId generateKey(
        boolean keyPresent, P11Slot slot, byte[] keyId, String keyLabel, String signatureAlgorithm)
        throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      int keysize = getKeysize(signatureAlgorithm);
      byte[] keyBytes = RandomUtil.nextBytes(keysize / 8);
      return slot.importSecretKey(PKCS11Constants.CKK_GENERIC_SECRET, keyBytes, getNewKeyControl(keyId, keyLabel));
    }

    private static int getKeysize(String hmacAlgorithm) {
      int keysize;
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
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

  public static class RSA extends P11SignSpeed {

    public RSA(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads, int keysize, BigInteger publicExponent)
        throws Exception {
      this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads,
          keysize, publicExponent);
    }

    public RSA(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
               String keyLabel, String signatureAlgorithm, int threads, int keysize, BigInteger publicExponent)
        throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keysize, publicExponent, keyLabel),
          "PKCS#11 RSA signature creation\n" + "keysize: " + keysize + "\n"
              + "public exponent: " + publicExponent, threads);
    }

    private static PKCS11KeyId generateKey(
        boolean keyPresent, P11Slot slot, byte[] keyId, int keysize, BigInteger publicExponent, String keyLabel)
        throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateRSAKeypair(keysize, publicExponent, getNewKeyControl(keyId, keyLabel));
    }

  } // class RSA

  public static class SM2 extends P11SignSpeed {

    public SM2(SecurityFactory securityFactory, P11Slot slot, byte[] keyId, int threads)
        throws Exception {
      this(true, securityFactory, slot, keyId, null, threads);
    }

    public SM2(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
               byte[] keyId, String keyLabel, int threads)
        throws Exception {
      super(securityFactory, slot, "SM3WITHSM2", !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel), "PKCS#11 SM2 signature creation", threads);
    }

    private static PKCS11KeyId generateKey(
        boolean keyPresent, P11Slot slot, byte[] keyId, String keyLabel)
        throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateSM2Keypair(getNewKeyControl(keyId, keyLabel));
    }

  } // class SM2

  private class Tester implements Runnable {

    private static final int batch = 10;

    private final byte[][] data = new byte[batch][16];

    public Tester() {
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
          LOG.error("P11SignSpeed.Tester.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(P11SignSpeed.class);

  private final P11Slot slot;

  private final ConcurrentContentSigner signer;

  private final PKCS11KeyId keyId;

  private final boolean deleteKeyAfterTest;

  public P11SignSpeed(SecurityFactory securityFactory, P11Slot slot, String signatureAlgorithm,
                      boolean deleteKeyAfterTest, PKCS11KeyId keyId, String description, int threads)
      throws ObjectCreationException {
    super(description + "\nsignature algorithm: " + signatureAlgorithm);

    notNull(securityFactory, "securityFactory");
    this.slot = notNull(slot, "slot");
    notBlank(signatureAlgorithm, "signatureAlgorithm");
    this.keyId = notNull(keyId, "keyId");

    this.deleteKeyAfterTest = deleteKeyAfterTest;

    P11SlotId slotId = slot.getSlotId();
    SignerConf signerConf = getPkcs11SignerConf(slot.getModuleName(),
        slotId.getId(), keyId.getId(), signatureAlgorithm, threads + Math.max(2, threads * 5 / 4));
    try {
      this.signer = securityFactory.createSigner("PKCS11", signerConf, (X509Cert) null);
    } catch (ObjectCreationException ex) {
      close();
      throw ex;
    }
  } // constructor

  @Override
  public final void close() {
    if (deleteKeyAfterTest) {
      try {
        LOG.info("delete key {}", keyId);
        slot.getKey(keyId).destroy();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not delete PKCS#11 key " + keyId);
      }
    }
  }

  protected static P11NewKeyControl getNewKeyControl(byte[] id, String label) {
    if (StringUtil.isBlank(label)) {
      label = "speed-" + Clock.systemUTC().millis();
    }
    return new P11NewKeyControl(id, label);
  }

  protected static PKCS11KeyId getNonNullKeyId(P11Slot slot, byte[] keyId, String keyLabel) throws TokenException {
    PKCS11KeyId p11Id = slot.getKeyId(keyId, keyLabel);
    if (p11Id == null) {
      throw new IllegalArgumentException("unknown key");
    }
    return p11Id;
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  private static SignerConf getPkcs11SignerConf(
      String pkcs11ModuleName, Long slotId, byte[] keyId, String signatureAlgorithm, int parallelism) {
    ConfPairs conf = new ConfPairs("algo", signatureAlgorithm)
                      .putPair("parallelism", Integer.toString(parallelism));

    if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
      conf.putPair("module", pkcs11ModuleName);
    }

    if (slotId != null) {
      conf.putPair("slot-id", slotId.toString());
    }

    if (keyId != null) {
      conf.putPair("key-id", Hex.encode(keyId));
    }

    return new SignerConf(conf.getEncoded());
  } // method getPkcs11SignerConf

}
