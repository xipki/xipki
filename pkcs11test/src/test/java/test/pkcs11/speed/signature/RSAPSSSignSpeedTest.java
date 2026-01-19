// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.signature;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.util.benchmark.BenchmarkExecutor;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKG_MGF1_SHA256;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS_PSS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * RSA/PSS sign / verify speed test.
 *
 * @author Lijun Liao (xipki)
 */

public class RSAPSSSignSpeedTest extends TestBase {

  @Override
  protected TestHSMs.TestHSM getHSM() {
    return TestHSMs.getHsmForSpeed();
  }

  private class MySignExecutor extends SignExecutor {

    public MySignExecutor() throws TokenException {
      super(ckmCodeToName(signMechanism) + " (2048) Sign Speed",
          signMechanism2, 32);
    }

    @Override
    protected PKCS11KeyPairSpec getMinimalKeyPairTemplate() {
      return getMinimalKeyPairTemplate0();
    }

  }

  private static final long keypairGenMechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

  private static final long signMechanism = CKM_RSA_PKCS;

  private final CkMechanism signMechanism2;

  private PKCS11KeyPairSpec getMinimalKeyPairTemplate0() {
    return new PKCS11KeyPairSpec().keyPairType(PKCS11KeyPairType.RSA_2048);
  }

  public RSAPSSSignSpeedTest() {
    signMechanism2 = new CkMechanism(CKM_RSA_PKCS_PSS,
        new RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32));
  }

  @Test
  public void main() throws TokenException {
    PKCS11Token token = getToken();

    Assume.assumeTrue(ckmCodeToName(keypairGenMechanism) +
            " is not supported, skip test",
        token.supportsMechanism(keypairGenMechanism, CKF_GENERATE_KEY_PAIR));

    Assume.assumeTrue(ckmCodeToName(signMechanism) +
            " is not supported, skip test",
        token.supportsMechanism(signMechanism, CKF_SIGN));

    BenchmarkExecutor executor = new MySignExecutor();
    executor.setThreads(TestHSMs.getSpeedThreads());
    executor.setDuration(TestHSMs.getSpeedDuration());
    executor.execute();
    Assert.assertEquals("Sign speed", 0,
        executor.getErrorAccount());
  }

}
