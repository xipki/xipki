// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.speed.SpeedExecutor;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.util.KeyUtil;


/**
 * P12 Keypair Gen Speed.
 *
 * @author Lijun Liao (xipki)
 */
public final class P12KeypairGenSpeed extends SpeedExecutor {

  private class Tester implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          generateKeypair();
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P12KeyGenSpeed.Tester.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(P12KeypairGenSpeed.class);

  private final KeySpec keySpec;

  public P12KeypairGenSpeed(KeySpec keySpec) {
    super("PKCS#12 keypair generation " + keySpec);
    this.keySpec = Args.notNull(keySpec, "keySpec");
  }

  private void generateKeypair() throws Exception {
    KeyUtil.generateKeyPair(keySpec);
  }

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

}
