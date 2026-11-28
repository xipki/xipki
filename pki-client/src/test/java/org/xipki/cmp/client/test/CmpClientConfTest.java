// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.cmp.client.CmpClientConf;
import org.xipki.codec.json.JsonParser;

/**
 * Parsing of the configuration of the CMP client.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpClientConfTest {

  @Test
  public void sendRequestorCertDefaultsToTrue() throws Exception {
    Assert.assertTrue(new CmpClientConf().isSendRequestorCert());
    Assert.assertTrue(CmpClientConf.parse(JsonParser.parseMap("{}", false))
        .isSendRequestorCert());
    Assert.assertFalse(CmpClientConf.parse(JsonParser.parseMap(
        "{\"sendRequestorCert\": false}", false)).isSendRequestorCert());
  }

  @Test
  public void sslIsOptional() throws Exception {
    Assert.assertNull(CmpClientConf.parse(JsonParser.parseMap("{}", false)).ssl());
  }

}
