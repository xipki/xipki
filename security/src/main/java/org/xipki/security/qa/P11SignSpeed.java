// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.util.benchmark.BenchmarkExecutor;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.RandomUtil;

import java.time.Clock;

/**
 * Speed test of PKCS#11 signature creation.
 *
 * @author Lijun Liao (xipki)
 */
public class P11SignSpeed extends BenchmarkExecutor {

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
      while (!stop() && getErrorAccount() < 1) {
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

  public P11SignSpeed(SecurityFactory securityFactory, P11Slot slot,
                      SignAlgo signAlgo, KeySpec keySpec, int threads)
      throws ObjectCreationException {
    super("PKCS#11 Sign speed test with signature algorithm "
        + signAlgo.jceName() + " and keyspec " + keySpec);
    Args.notNull(securityFactory, "securityFactory");

    this.slot = Args.notNull(slot, "slot");
    this.keyId = generateKey(signAlgo, keySpec);

    P11SlotId slotId = slot.slotId();
    SignerConf signerConf = getPkcs11SignerConf(slot.moduleName(),
        slotId.id(), keyId.getId(),
        Args.notNull(signAlgo, "signAlgo"),
        threads + Math.max(2, threads * 5 / 4));
    try {
      this.signer = securityFactory.createSigner("PKCS11", signerConf,
          (X509Cert) null);
    } catch (ObjectCreationException ex) {
      close();
      throw ex;
    }
  } // constructor

  @Override
  public final void close() {
    try {
      LOG.info("delete key {}", keyId);
      slot.getKey(keyId).destroy();
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not delete PKCS#11 key " + keyId);
    }
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  private static SignerConf getPkcs11SignerConf(
      String pkcs11ModuleName, Long slotId, byte[] keyId,
      SignAlgo signAlgo, int parallelism) {
    SignerConf conf = new SignerConf()
        .setAlgo(signAlgo)
        .setParallelism(parallelism);

    if (pkcs11ModuleName != null && !pkcs11ModuleName.isEmpty()) {
      conf.setModule(pkcs11ModuleName);
    }

    if (slotId != null) {
      conf.setSlotId(slotId);
    }

    if (keyId != null) {
      conf.setKeyId(keyId);
    }

    return conf;
  }

  private PKCS11KeyId generateKey(SignAlgo signAlgo, KeySpec keySpec)
      throws ObjectCreationException {

    try {
      Integer keysize = P12SignSpeed.getSymmKeyBitSize(signAlgo);
      if (keysize != null) {
        if (keySpec != null) {
          throw new IllegalArgumentException(
              "keySpec shall not be non-null: " + keySpec);
        }

        // symmetric key
        long keyType;
        switch (signAlgo) {
          case GMAC_AES128:
          case GMAC_AES192:
          case GMAC_AES256:
            keyType = PKCS11T.CKK_AES;
            break;
          default:
            keyType = PKCS11T.CKK_GENERIC_SECRET;
        }

        byte[] keyValue = RandomUtil.nextBytes((keysize + 7) / 8);

        String label = "speed-" + Clock.systemUTC().millis();
        PKCS11SecretKeySpec spec = new PKCS11SecretKeySpec()
            .id(RandomUtil.nextBytes(8)).label(label).keyType(keyType);

        return slot.importSecretKey(keyValue, spec);
      } else {
        if (keySpec == null) {
          keySpec = P12SignSpeed.getKeySpec(signAlgo);
          if (keySpec == null) {
            throw new IllegalArgumentException(
                "cannot determine keyspec from signAlgo " + signAlgo);
          }
        }

        String label = "speed-" + Clock.systemUTC().millis();
        PKCS11KeyPairSpec spec = new PKCS11KeyPairSpec()
            .id(RandomUtil.nextBytes(8)).label(label);

        return slot.generateKeyPair(keySpec, spec);
      }
    } catch (TokenException e) {
      throw new ObjectCreationException(e);
    }
  }

}
