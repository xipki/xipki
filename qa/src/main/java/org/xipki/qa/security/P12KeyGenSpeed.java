/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.math.BigInteger;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12KeyGenSpeed extends BenchmarkExecutor {

  // CHECKSTYLE:SKIP
  public static class DSA extends P12KeyGenSpeed {
    private final int plength;
    private final int qlength;

    public DSA(int plength, int qlength, SecurityFactory securityFactory) throws Exception {
      super("PKCS#12 DSA key generation\nplength: " + plength + "\nqlength: " + qlength,
          securityFactory);

      this.plength = plength;
      this.qlength = qlength;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      KeyUtil.generateDSAKeypair(plength, qlength, random);
    }

  }

  // CHECKSTYLE:SKIP
  public static class EC extends P12KeyGenSpeed {

    private final String curveOidOrName;

    public EC(String curveNameOrOid, SecurityFactory securityFactory) throws Exception {
      super("PKCS#12 EC key generation\ncurve: " + curveNameOrOid, securityFactory);
      this.curveOidOrName = curveNameOrOid;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      if (EdECConstants.isEdwardsOrMontgemoryCurve(curveOidOrName)) {
        KeyUtil.generateEdECKeypair(curveOidOrName, random);
      } else {
        KeyUtil.generateECKeypairForCurveNameOrOid(curveOidOrName, random);
      }
    }

  }

  // CHECKSTYLE:SKIP
  public static class RSA extends P12KeyGenSpeed {

    private final int keysize;
    private final BigInteger publicExponent;

    public RSA(int keysize, BigInteger publicExponent, SecurityFactory securityFactory)
        throws Exception {
      super("PKCS#12 RSA key generation\nkeysize: " + keysize
          + "\npublic exponent: " + publicExponent, securityFactory);

      this.keysize = keysize;
      this.publicExponent = publicExponent;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    }

  }

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          generateKeypair(securityFactory.getRandom4Key());
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P12KeyGenSpeed.Testor.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Testor

  private static final Logger LOG = LoggerFactory.getLogger(P12KeyGenSpeed.class);

  private final SecurityFactory securityFactory;

  public P12KeyGenSpeed(String description, SecurityFactory securityFactory) {
    super(description);
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  protected abstract void generateKeypair(SecureRandom random) throws Exception;

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

}
