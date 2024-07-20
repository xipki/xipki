// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.PKCS1Util;

import java.security.SecureRandom;

/**
 * Test for {@link PKCS1Util}.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class PKCS1UtilTest {

  @Test
  public void testMgf1PssEncodeDecode() throws XiSecurityException {
    HashAlgo ha = HashAlgo.SHA256;
    byte[] mHash = ha.hash("hello world".getBytes());
    int modulusBits = 2048;
    int sLen = ha.getLength();
    byte[] em = PKCS1Util.EMSA_PSS_ENCODE(ha, mHash, ha, sLen, modulusBits, new SecureRandom());
    boolean valid = PKCS1Util.EMSA_PSS_DECODE(ha, mHash, em, sLen, modulusBits);
    Assert.assertTrue("PSS encode-then-decode", valid);
  }

  @Test
  public void testShakePssEncodeDecode() throws XiSecurityException {
    HashAlgo ha = HashAlgo.SHAKE128;
    byte[] mHash = ha.hash("hello world".getBytes());
    int modulusBits = 2048;
    int sLen = ha.getLength();
    byte[] em = PKCS1Util.EMSA_PSS_ENCODE(ha, mHash, ha, sLen, modulusBits, new SecureRandom());
    boolean valid = PKCS1Util.EMSA_PSS_DECODE(ha, mHash, em, sLen, modulusBits);
    Assert.assertTrue("PSS encode-then-decode", valid);
  }

}
