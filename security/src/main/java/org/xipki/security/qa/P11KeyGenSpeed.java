// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.qa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;

/**
 * Speed test of PKCS#11 keypair generation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P11KeyGenSpeed extends BenchmarkExecutor {

  public static class DSA extends P11KeyGenSpeed {

    private final int plength;

    private final int qlength;

    public DSA(P11Slot slot, int plength, int qlength) {
      super(slot, "PKCS#11 DSA key generation\nplength: " + plength + "\nqlength: " + qlength);
      this.plength = plength;
      this.qlength = qlength;
    }

    @Override
    protected void genKeypair() throws Exception {
      DSAParameterSpec spec = DSAParameterCache.getDSAParameterSpec(plength, qlength, null);
      slot.generateDSAKeypairOtf(spec.getP(), spec.getQ(), spec.getG());
    }

  } // class DSA

  public static class EC extends P11KeyGenSpeed {

    private final ASN1ObjectIdentifier curveOid;

    public EC(P11Slot slot, ASN1ObjectIdentifier curveOid) {
      super(slot, "PKCS#11 EC key generation\ncurve: " + AlgorithmUtil.getCurveName(curveOid));
      this.curveOid = Args.notNull(curveOid, "curveOid");
    }

    @Override
    protected void genKeypair() throws Exception {
      slot.generateECKeypairOtf(curveOid);
    }

  } // class EC

  public static class RSA extends P11KeyGenSpeed {

    private final int keysize;

    private final BigInteger publicExponent;

    public RSA(P11Slot slot, int keysize, BigInteger publicExponent) {
      super(slot, "PKCS#11 RSA key generation\nkeysize: " + keysize
          + "\npublic exponent: " + publicExponent);
      this.keysize = keysize;
      this.publicExponent = publicExponent;
    }

    @Override
    protected void genKeypair() throws Exception {
      slot.generateRSAKeypairOtf(keysize, publicExponent);
    }

  } // class RSA

  public static class SM2 extends P11KeyGenSpeed {
    public SM2(P11Slot slot) {
      super(slot, "PKCS#11 SM2 key generation");
    }

    @Override
    protected void genKeypair() throws Exception {
      slot.generateSM2KeypairOtf();
    }

  } // class SM2

  class Tester implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          genKeypair();
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P11KeyGenSpeed.Tester.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Tester

  protected final P11Slot slot;

  private static final Logger LOG = LoggerFactory.getLogger(P11KeyGenSpeed.class);

  public P11KeyGenSpeed(P11Slot slot, String description) {
    super(description);
    this.slot = Args.notNull(slot, "slot");
  }

  protected abstract void genKeypair() throws Exception;

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

}
