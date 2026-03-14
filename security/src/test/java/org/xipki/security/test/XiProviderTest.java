// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;
import org.xipki.security.provider.XiPKIProvider;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Hex;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * Test for {@link XiPKIProvider}.
 *
 * @author Lijun Liao (xipki)
 */
public class XiProviderTest {

  private static final SecureRandom rnd = new SecureRandom();

  private static final Provider bcProv;

  private static final Provider xiProv = new XiPKIProvider(true, true);

  static {
    KeyUtil.addProviders();
    bcProv = Security.getProvider("BC");
  }

  private static byte[] rndBytes(int size) {
    byte[] m = new byte[size];
    rnd.nextBytes(m);
    return m;
  }

  private static void assumeBcAvailable() {
    Assume.assumeTrue("Provider BC is not available", bcProv != null);
  }

  @Test
  public void sm2DigestCrossCheck() throws Exception {
    assumeBcAvailable();
    HashAlgo hashAlgo = HashAlgo.SM3;
    byte[] m = rndBytes(100);
    byte[] bcHash = hash(hashAlgo, m, bcProv);
    byte[] xiHash = hash(hashAlgo, m, xiProv);
    Assert.assertEquals("SM3 hash", Hex.encode(bcHash), Hex.encode(xiHash));
  }

  @Test
  public void sm2sm3Sign() throws Exception {
    signCheck(SignAlgo.SM2_SM3, KeySpec.SM2, xiProv, xiProv);
  }

  @Test
  public void sm2sm3SignCrossCheck() throws Exception {
    signCrossCheck(SignAlgo.SM2_SM3, KeySpec.SM2);
  }

  @Test
  public void shake128SignCheck() throws Exception {
    signCheck(SignAlgo.RSAPSS_SHAKE128, KeySpec.RSA2048, xiProv, xiProv);
  }

  @Test
  public void shake128SignCrossCheck() throws Exception {
    signCrossCheck(SignAlgo.RSAPSS_SHAKE128, KeySpec.RSA2048);
  }

  @Test
  public void shake256SignCheck() throws Exception {
    signCheck(SignAlgo.RSAPSS_SHAKE256, KeySpec.RSA2048, xiProv, xiProv);
  }

  @Test
  public void shake256SignCrossCheck() throws Exception {
    signCrossCheck(SignAlgo.RSAPSS_SHAKE256, KeySpec.RSA2048);
  }

  private void signCrossCheck(SignAlgo signAlgo, KeySpec keySpec)
      throws Exception {
    assumeBcAvailable();
    signCheck(signAlgo, keySpec, bcProv, xiProv);
  }

  private void signCheck(SignAlgo signAlgo, KeySpec keySpec,
                        Provider prov1, Provider prov2)
      throws Exception {
    byte[] m = rndBytes(100);

    KeyPair keyPair = KeyUtil.generateKeyPair(keySpec, rnd);

    byte[] sig1 = sign(signAlgo, m, prov1, keyPair.getPrivate());
    verify(signAlgo, m, sig1, prov2, keyPair.getPublic());

    byte[] sig2 = sign(signAlgo, m, prov2, keyPair.getPrivate());
    verify(signAlgo, m, sig2, prov1, keyPair.getPublic());
  }

  private static byte[] hash(HashAlgo hashAlgo, byte[] m, Provider prov)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance(hashAlgo.jceName(), prov);
    md.update(m);
    return md.digest();
  }

  private static byte[] sign( SignAlgo signAlgo, byte[] m, Provider prov, PrivateKey key)
      throws Exception {
    Signature sig = Signature.getInstance(signAlgo.jceName(), prov);
    sig.initSign(key, rnd);
    sig.update(m);
    return sig.sign();
  }

  private static void verify(
      SignAlgo signAlgo, byte[] m, byte[] sigValue, Provider prov, PublicKey key)
      throws Exception {
    Signature sig = Signature.getInstance(signAlgo.jceName(), prov);
    sig.initVerify(key);
    sig.update(m);
    boolean valid = sig.verify(sigValue);
    Assert.assertTrue("signature is not valid", valid);
  }

}
