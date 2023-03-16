/*
 *
 * Copyright (c) 2013 - 2023 Lijun Liao
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
 * @author Lijun Liao
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
