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

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.*;

import java.math.BigInteger;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Speed test of PKCS#11 signature creation.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11SignSpeed extends BenchmarkExecutor {

  public static class DSA extends P11SignSpeed {

    public DSA(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads, int plength, int qlength)
            throws Exception {
      this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads,
          plength, qlength);
    }

    public DSA(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads,
        int plength, int qlength)
            throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, plength, qlength),
          "PKCS#11 DSA signature creation\npLength: " + plength + "\nqLength: " + qlength, threads);
    }

    private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot, byte[] keyId,
        String keyLabel, int plength, int qlength)
            throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateDSAKeypair(plength, qlength, getNewKeyControl(keyId, keyLabel))
                .getKeyId();
    }

  } // class DSA

  public static class EC extends P11SignSpeed {

    public EC(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads, ASN1ObjectIdentifier curveOid)
            throws Exception {
      this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads, curveOid);
    }

    public EC(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads,
        ASN1ObjectIdentifier curveOid)
            throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, curveOid),
          "PKCS#11 EC signature creation\ncurve: " + AlgorithmUtil.getCurveName(curveOid), threads);
    }

    private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot, byte[] keyId,
        String keyLabel, ASN1ObjectIdentifier curveOid)
            throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateECKeypair(curveOid, getNewKeyControl(keyId, keyLabel)).getKeyId();
    }

  } // class EC

  public static class HMAC extends P11SignSpeed {

    public HMAC(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
        String signatureAlgorithm, int threads)
            throws Exception {
      this(!false, securityFactory, slot, keyId, null, signatureAlgorithm, threads);
    }

    public HMAC(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads)
            throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel, signatureAlgorithm),
          "PKCS#11 HMAC signature creation", threads);
    }

    private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm)
            throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      int keysize = getKeysize(signatureAlgorithm);
      byte[] keyBytes = RandomUtil.nextBytes(keysize / 8);
      return slot.importSecretKey(PKCS11Constants.CKK_GENERIC_SECRET, keyBytes,
          getNewKeyControl(keyId, keyLabel));
    }

    private static int getKeysize(String hmacAlgorithm) {
      int keysize;
      hmacAlgorithm = hmacAlgorithm.toUpperCase();
      if ("HMACSHA1".equals(hmacAlgorithm)) {
        keysize = 160;
      } else if ("HMACSHA224".equals(hmacAlgorithm)
          || "HMACSHA3-224".equals(hmacAlgorithm)) {
        keysize = 224;
      } else if ("HMACSHA256".equals(hmacAlgorithm)
          || "HMACSHA3-256".equals(hmacAlgorithm)) {
        keysize = 256;
      } else if ("HMACSHA384".equals(hmacAlgorithm)
          || "HMACSHA3-384".equals(hmacAlgorithm)) {
        keysize = 384;
      } else if ("HMACSHA512".equals(hmacAlgorithm)
          || "HMACSHA3-512".equals(hmacAlgorithm)) {
        keysize = 512;
      } else {
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

    public RSA(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, String signatureAlgorithm, int threads, int keysize,
        BigInteger publicExponent)
            throws Exception {
      super(securityFactory, slot, signatureAlgorithm, !keyPresent,
          generateKey(keyPresent, slot, keyId, keysize, publicExponent, keyLabel),
          "PKCS#11 RSA signature creation\n" + "keysize: " + keysize + "\n"
              + "public exponent: " + publicExponent, threads);
    }

    private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot, byte[] keyId,
        int keysize, BigInteger publicExponent, String keyLabel)
            throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateRSAKeypair(keysize, publicExponent, getNewKeyControl(keyId, keyLabel))
              .getKeyId();
    }

  } // class RSA

  public static class SM2 extends P11SignSpeed {

    public SM2(SecurityFactory securityFactory, P11Slot slot, byte[] keyId, int threads)
        throws Exception {
      this(!false, securityFactory, slot, keyId, null, threads);
    }

    public SM2(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
        byte[] keyId, String keyLabel, int threads)
            throws Exception {
      super(securityFactory, slot, "SM3WITHSM2", !keyPresent,
          generateKey(keyPresent, slot, keyId, keyLabel), "PKCS#11 SM2 signature creation",
              threads);
    }

    private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot,
        byte[] keyId, String keyLabel)
            throws Exception {
      if (keyPresent) {
        return getNonNullKeyId(slot, keyId, keyLabel);
      }

      return slot.generateSM2Keypair(getNewKeyControl(keyId, keyLabel)).getKeyId();
    }

  } // class SM2

  class Testor implements Runnable {

    private static final int batch = 10;

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
          LOG.error("P11SignSpeed.Testor.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Testor

  private static final Logger LOG = LoggerFactory.getLogger(P11SignSpeed.class);

  private final P11Slot slot;

  private final ConcurrentContentSigner signer;

  private final P11ObjectIdentifier objectId;

  private final boolean deleteKeyAfterTest;

  public P11SignSpeed(SecurityFactory securityFactory, P11Slot slot, String signatureAlgorithm,
      boolean deleteKeyAfterTest, P11ObjectIdentifier objectId, String description, int threads)
          throws ObjectCreationException {
    super(description + "\nsignature algorithm: " + signatureAlgorithm);

    notNull(securityFactory, "securityFactory");
    this.slot = notNull(slot, "slot");
    notBlank(signatureAlgorithm, "signatureAlgorithm");
    this.objectId = notNull(objectId, "objectId");

    this.deleteKeyAfterTest = deleteKeyAfterTest;

    P11SlotIdentifier slotId = slot.getSlotId();
    SignerConf signerConf = getPkcs11SignerConf(slot.getModuleName(),
        slotId.getId(), objectId.getId(), signatureAlgorithm,
        threads + Math.max(2, threads * 5 / 4));
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
        LOG.info("delete key {}", objectId);
        slot.removeIdentityByKeyId(objectId);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not delete PKCS#11 key " + objectId);
      }
    }
  }

  protected static P11NewKeyControl getNewKeyControl(byte[] id, String label) {
    if (StringUtil.isBlank(label)) {
      label = "speed-" + System.currentTimeMillis();
    }
    return new P11NewKeyControl(id, label);
  }

  protected static P11ObjectIdentifier getNonNullKeyId(P11Slot slot,
      byte[] keyId, String keyLabel) {
    P11IdentityId p11Id = slot.getIdentityId(keyId, keyLabel);
    if (p11Id == null) {
      throw new IllegalArgumentException("unknown key");
    }
    return p11Id.getKeyId();
  }

  @Override
  protected Runnable getTestor()
      throws Exception {
    return new Testor();
  }

  private static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Long slotId, byte[] keyId,
      String signatureAlgorithm, int parallelism) {
    ConfPairs conf = new ConfPairs("algo", signatureAlgorithm);
    conf.putPair("parallelism", Integer.toString(parallelism));

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
