// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Speed test of PKCS#12 keypair generation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P12KeyGenSpeed extends BenchmarkExecutor {

  public static class DSA extends P12KeyGenSpeed {
    private final int plength;
    private final int qlength;

    public DSA(int plength, int qlength, SecurityFactory securityFactory) {
      super("PKCS#12 DSA key generation\nplength: " + plength + "\nqlength: " + qlength, securityFactory);

      this.plength = plength;
      this.qlength = qlength;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      KeyUtil.generateDSAKeypair(plength, qlength, random);
    }

  } // class DSA

  public static class EC extends P12KeyGenSpeed {

    private final ASN1ObjectIdentifier curveOid;

    public EC(ASN1ObjectIdentifier curveOid, SecurityFactory securityFactory) {
      super("PKCS#12 EC key generation\ncurve: " + AlgorithmUtil.getCurveName(curveOid), securityFactory);
      this.curveOid = curveOid;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      if (EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)) {
        KeyUtil.generateEdECKeypair(curveOid, random);
      } else {
        KeyUtil.generateECKeypair(curveOid, random);
      }
    }

  } // class EC

  public static class RSA extends P12KeyGenSpeed {

    private final int keysize;
    private final BigInteger publicExponent;

    public RSA(int keysize, BigInteger publicExponent, SecurityFactory securityFactory) {
      super("PKCS#12 RSA key generation\nkeysize: " + keysize
          + "\npublic exponent: " + publicExponent, securityFactory);

      this.keysize = keysize;
      this.publicExponent = publicExponent;
    }

    @Override
    protected void generateKeypair(SecureRandom random) throws Exception {
      KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    }

  } // class RSA

  private class Tester implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          generateKeypair(securityFactory.getRandom4Key());
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P12KeyGenSpeed.Tester.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(P12KeyGenSpeed.class);

  private final SecurityFactory securityFactory;

  public P12KeyGenSpeed(String description, SecurityFactory securityFactory) {
    super(description);
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  protected abstract void generateKeypair(SecureRandom random) throws Exception;

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

}
