// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.ca.api.profile.TextVadidator;

/**
 * TextValidator test.
 * @author Lijun Liao (xipki)
 *
 */
public class TextValidatorTest {

  @Test
  public void testFQDN() {
    TextVadidator tv = TextVadidator.compile(":FQDN");

    String[] strs = {"pki.goog", "abc.com", "*.abc.com", "abc.local", "a.root"};
    for (String str : strs) {
      Assert.assertTrue(str, tv.isValid(str));
    }
  }

}
