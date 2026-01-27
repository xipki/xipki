// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.speed.Pkcs11Executor;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

/**
 * Keypair generation executor base class.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class KeypairGenExecutor extends Pkcs11Executor {

  private static final Logger LOG =
      LoggerFactory.getLogger(KeypairGenExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate keypair on token
          PKCS11KeyPairSpec template = getMinimalKeyPairTemplate()
              .token(inToken).signVerify(true)
              .sensitive(true).private_(true);

          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            template.id(id);
          }

          PKCS11KeyId keypair = TestHSMs.getHsmForSpeed().getToken()
              .generateKeyPair(template);
          destroyKey(LOG, keypair);

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

  public KeypairGenExecutor(String description, long mechanism,
                            boolean inToken) {
    super(description);
    this.mechanism = new CkMechanism(mechanism);
    this.inToken = inToken;
  }

  protected abstract PKCS11KeyPairSpec getMinimalKeyPairTemplate();

  @Override
  protected Runnable getTester() {
    return new MyRunnable();
  }

}
