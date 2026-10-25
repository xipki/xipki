// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.qa;

import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.codec.util.IoUtil;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Generate Key Pool Resources Main.
 *
 * @author Lijun Liao (xipki)
 */
public class GenerateKeyPoolResourcesMain {

  public static void main(String[] args) {
    int n = 10;

    SecureRandom rnd = new SecureRandom();
    for (KeySpec keySpec : KeySpec.values()) {
      if (!keySpec.name().contains("RSA")) {
        continue;
      }

      try {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
          KeyPairWithSubjectPublicKeyInfo kp2 = KeyUtil.generateKeyPair2(keySpec, rnd);
          byte[] encodedSk = kp2.keypair().getPrivate().getEncoded();
          byte[] encodedPk = kp2.subjectPublicKeyInfo().getEncoded();
          PrivateKeyInfo.fromEncoded(encodedSk);
          sb.append(Base64.encodeToString(encodedSk)).append(":")
              .append(Base64.encodeToString(encodedPk)).append("\n");
        }

        IoUtil.save("qa/target/keypool/" + keySpec.name() + ".txt",
            sb.toString().getBytes(StandardCharsets.UTF_8));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

}
