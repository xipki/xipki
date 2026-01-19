// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.KeyPairTemplate;
import test.pkcs11.wrapper.TestBase;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;

/**
 * @author Lijun Liao (xipki)
 */
public class ImportKeyPairTest {

  private static abstract class Base extends TestBase {

    private void testImport(KeyPair keyPair, KeyPairTemplate template)
        throws Exception {
      String label = "test-" + UUID.randomUUID() + "-" +
          System.currentTimeMillis();
      template.labels(label);
    }

    @Test
    public void testRSA() throws Exception {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
      kpGen.initialize(2048);

      KeyPairTemplate template = new KeyPairTemplate().signVerify(true);
      testImport(kpGen.generateKeyPair(), template);
    }
  }

}
