// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.speed.Pkcs11Executor;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * Secret key generation executor base class.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class KeyGenExecutor extends Pkcs11Executor {

  private static final Logger LOG =
      LoggerFactory.getLogger(KeyGenExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate key on token
          PKCS11SecretKeySpec secretKeyTemplate = getMinimalKeyTemplate()
              .token(inToken).sensitive(true).encrypt(true).decrypt(true);
          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            secretKeyTemplate.id(id);
          }

          PKCS11KeyId key = TestHSMs.getHsmForSpeed().getToken()
              .generateKey(secretKeyTemplate);
          destroyKey(LOG, key);

          account(1, 0);
        } catch (Throwable th) {
          System.err.println(th.getMessage());
          LOG.error("error", th);
          account(1, 1);
        }
      }
    }

  }

  private final CkMechanism mechanism;

  private final boolean inToken;

  public KeyGenExecutor(long mechanism, int keyLen, boolean inToken) {
    super(describe(mechanism, keyLen, inToken));
    this.mechanism = new CkMechanism(mechanism);
    this.inToken = inToken;
  }

  protected abstract PKCS11SecretKeySpec getMinimalKeyTemplate();

  @Override
  protected Runnable getTester() {
    return new MyRunnable();
  }

  private static String describe(long mechanism, int keyLen, boolean inToken) {
    StringBuilder sb = new StringBuilder(100)
      .append(ckmCodeToName(mechanism)).append(" (");
    if (keyLen > 0) {
      sb.append(keyLen * 8).append(" bits, ");
    }

    sb.append("inToken: ").append(inToken).append(") Speed");
    return sb.toString();
  }

}
