// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.SignAlgo;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * @author Lijun Liao (xipki)
 */
public class CompositeSigTest {

  static final byte[] m = Base64.decode(
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=");

  @Test
  public void test() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(KeyUtil.newBouncyCastleProvider());
    }

    SecureRandom rnd = new SecureRandom();
    for (SignAlgo algoSuite : SignAlgo.values()) {
      if (algoSuite.isCompositeMLDSA()) {
        singleTest2(algoSuite, rnd);
      }
    }
  }

  private static void singleTest2(
      SignAlgo algo, SecureRandom rnd)
      throws Exception {
    System.out.println("===== BEGIN testing " + algo + " =====");
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(
        algo.jceName(), "BC");
    KeyPair kp = kpGen.generateKeyPair();

    SignAlgo signAlgo = SignAlgo.getInstance(kp.getPrivate());
    Assert.assertEquals(algo, signAlgo);

    Signature sig = Signature.getInstance(algo.jceName(), "BC");
    sig.initSign(kp.getPrivate(), rnd);

    String keyAlgo = kp.getPrivate().getAlgorithm();
    if (!keyAlgo.equals(algo.jceName())) {
      System.out.println(keyAlgo);
      System.out.println(algo.jceName());
    }
    sig.update(m);
    byte[] sigValue = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(m);
    boolean sigValid = sig.verify(sigValue);
    Assert.assertTrue("message is not valid", sigValid);
  }

}
