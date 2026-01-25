package org.xipki.qa;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.security.KeySpec;
import org.xipki.security.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Base64;
import org.xipki.util.io.IoUtil;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class GenerateKeyPoolResourcesMain {

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    int n = 10;

    SecureRandom rnd = new SecureRandom();
    for (KeySpec keySpec : KeySpec.values()) {
      if (!keySpec.name().contains("RSA")) {
        continue;
      }

      try {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
          KeyPairWithSubjectPublicKeyInfo kp2 =
              KeyUtil.generateKeypair2(keySpec, rnd);
          byte[] encodedSk = kp2.getKeypair().getPrivate().getEncoded();
          byte[] encodedPk = kp2.getSubjectPublicKeyInfo().getEncoded();
          PrivateKeyInfo.getInstance(encodedSk);
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
