// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.speed.Pkcs11Executor;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

/**
 * Sign executor base class.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class SignExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(SignExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          byte[] data = TestBase.randomBytes(inputLen);
          TestHSMs.getHsmForSpeed().getToken()
              .sign(signMechanism, keypair.getHandle(), data);
          account(1, 0);
        } catch (Throwable th) {
          System.err.println(th.getMessage());
          LOG.error("error", th);
          account(1, 1);
        }
      }
    }

  }

  private final CkMechanism signMechanism;

  private final int inputLen;

  private final PKCS11KeyId keypair;

  public SignExecutor(String description, CkMechanism signMechanism,
                      int inputLen)
          throws TokenException {
    super(description);
    this.signMechanism = signMechanism;
    this.inputLen = inputLen;

    byte[] id = new byte[20];
    new Random().nextBytes(id);

    PKCS11KeyPairSpec template = getMinimalKeyPairTemplate()
        .token(true).id(id).signVerify(true).sensitive(true).private_(true);

    // generate keypair on token
    keypair = TestHSMs.getHsmForSpeed().getToken().generateKeyPair(template);
  }

  protected abstract PKCS11KeyPairSpec getMinimalKeyPairTemplate();

  @Override
  protected Runnable getTester() {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (keypair != null) {
      try {
        PKCS11Token token = TestHSMs.getHsmForSpeed().getToken();
        token.destroyKey(keypair);
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      }
    }

    super.close();
  }

}
