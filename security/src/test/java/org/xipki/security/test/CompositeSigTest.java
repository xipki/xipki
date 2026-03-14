// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompositeSigSuite;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Base64;

import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * @author Lijun Liao (xipki)
 */
public class CompositeSigTest {

  static final byte[] m = Base64.decode(
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=");

  @Test
  public void test() throws Exception {
    KeyUtil.addProviders();
    SecureRandom rnd = new SecureRandom();
    for (CompositeSigSuite suite : CompositeSigSuite.values()) {
      singleTest2(suite, rnd);
    }
  }

  private static void singleTest2(CompositeSigSuite suite, SecureRandom rnd)
      throws Exception {
    System.out.println("===== BEGIN testing " + suite + " =====");
    KeyPair kp = KeyUtil.generateKeyPair(suite.keySpec(), rnd);

    SignAlgo signAlgo = SignAlgo.getInstance(kp.getPrivate());
    Assert.assertEquals(suite, signAlgo.compositeSigAlgoSuite());

    Signer signer = KeyUtil.getSigner(kp.getPrivate(), kp.getPublic(), rnd);
    byte[] sigValue = signer.x509Sign(m);

    ContentVerifierProvider verifierProvider =
        KeyUtil.getContentVerifierProvider(kp.getPublic());
    ContentVerifier verifier =
        verifierProvider.get(signAlgo.algorithmIdentifier());
    verifier.getOutputStream().write(m);
    boolean sigValid = verifier.verify(sigValue);
    Assert.assertTrue("message is not valid", sigValid);
  }

}
