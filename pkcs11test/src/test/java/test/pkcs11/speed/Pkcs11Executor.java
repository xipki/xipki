// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed;

import org.slf4j.Logger;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.util.benchmark.BenchmarkExecutor;
import test.pkcs11.wrapper.TestHSMs;

/**
 * Benchmark executor base class.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Pkcs11Executor extends BenchmarkExecutor {

  protected Pkcs11Executor(String description) {
    super(description);
  }

  protected static void destroyKey(Logger logger, PKCS11KeyId keyId) {
    try {
      TestHSMs.getHsmForSpeed().getToken().destroyKey(keyId);
    } catch (TokenException ex) {
      logger.error("could not destroy key {}", keyId);
    }
  }

}
