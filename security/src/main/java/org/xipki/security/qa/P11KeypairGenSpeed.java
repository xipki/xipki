// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.KeySpec;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.util.benchmark.BenchmarkExecutor;
import org.xipki.util.codec.Args;

/**
 * Speed test of PKCS#11 keypair generation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public final class P11KeypairGenSpeed extends BenchmarkExecutor {

  class Tester implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          genKeyPair();
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P11KeyGenSpeed.Tester.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Tester

  private final P11Slot slot;

  private final KeySpec keySpec;

  private static final Logger LOG =
      LoggerFactory.getLogger(P11KeypairGenSpeed.class);

  public P11KeypairGenSpeed(P11Slot slot, KeySpec keySpec) {
    super("PKCS#11 key generation: " + keySpec.name());
    this.slot = Args.notNull(slot, "slot");
    this.keySpec = keySpec;
  }

  private void genKeyPair() throws Exception {
    slot.generateKeyPairOtf(keySpec);
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

}
