/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs12.test;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs12.KeypairWithCert;
import org.xipki.security.pkcs12.P12ContentSignerBuilder;
import org.xipki.security.util.X509Util;

/**
 * Abstract class of JUnit tests to test the signature creation and verification
 * of PKCS#12 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public abstract class Pkcs12SignVerifyTest {

  private ConcurrentContentSigner signer;

  protected Pkcs12SignVerifyTest() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  protected abstract SignAlgo getSignatureAlgorithm();

  protected abstract String getPkcs12File();

  protected abstract String getCertificateFile();

  protected String getPassword() {
    return "1234";
  }

  private ConcurrentContentSigner getSigner()
      throws Exception {
    if (signer != null) {
      return signer;
    }

    String certFile = getCertificateFile();
    X509Cert cert = X509Util.parseCert(new File(certFile));

    InputStream ks = Files.newInputStream(Paths.get(getPkcs12File()));
    char[] password = getPassword().toCharArray();
    KeypairWithCert keypairWithCert = KeypairWithCert.fromKeystore("PKCS12", ks,
        password, null, password, cert);
    P12ContentSignerBuilder builder = new P12ContentSignerBuilder(keypairWithCert);
    signer = builder.createSigner(getSignatureAlgorithm(), 1, new SecureRandom());
    return signer;
  }

  @Test
  public void testSignAndVerify()
      throws Exception {
    byte[] data = new byte[1234];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i & 0xFF);
    }

    byte[] signatureValue = sign(data);
    boolean signatureValid = verify(data, signatureValue, getSigner().getCertificate());
    Assert.assertTrue("Signature invalid", signatureValid);
  }

  protected byte[] sign(byte[] data)
      throws Exception {
    return getSigner().sign(data);
  }

  protected boolean verify(byte[] data, byte[] signatureValue, X509Cert cert)
      throws Exception {
    Signature signature = Signature.getInstance(getSignatureAlgorithm().getJceName());
    signature.initVerify(cert.getPublicKey());
    signature.update(data);
    return signature.verify(signatureValue);
  }

}
