// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import test.pkcs11.wrapper.TestBase;

import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Signature test base
 *
 * @author Lijun Liao (xipki)
 */
public abstract class SignatureTestBase extends TestBase {

  @BeforeClass
  public static void addProvider() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  protected void jceVerifySignature(
      String algorithm, long publicKeyHandle, long keyType,
      byte[] data, byte[] signatureValue) throws Exception {
    // verify with JCE
    PublicKey jcePublicKey = generateJCEPublicKey(publicKeyHandle, keyType);
    Signature signature = Signature.getInstance(algorithm, "BC");
    signature.initVerify(jcePublicKey);
    signature.update(data);
    boolean valid = signature.verify(signatureValue);
    if (!valid) {
      throw new SignatureException("signature is invalid");
    }
  }

}
