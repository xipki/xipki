// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.benchmark.BenchmarkExecutor;

import java.security.SecureRandom;

/**
 * P12 Keypair Gen Speed.
 *
 * @author Lijun Liao (xipki)
 */
public final class P12KeypairGenSpeed extends BenchmarkExecutor {

  private class Tester implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          generateKeypair(securityFactory.random4Key());
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P12KeyGenSpeed.Tester.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(P12KeypairGenSpeed.class);

  private final SecurityFactory securityFactory;

  private final KeySpec keySpec;

  public P12KeypairGenSpeed(KeySpec keySpec, SecurityFactory securityFactory) {
    super("PKCS#12 keypair generation " + keySpec);
    this.keySpec = Args.notNull(keySpec, "keySpec");
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  private void generateKeypair(SecureRandom random) throws Exception {
    KeyUtil.generateKeyPair(keySpec, random);
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

}
