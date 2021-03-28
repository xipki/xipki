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

package org.xipki.scep.example;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.IoUtil;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SCEP client example with concrete test data.
 *
 * @author Lijun Liao
 */

public class ScepClientExample extends CaClientExample {

  private static final String CA_URL = "http://localhost:8080/scep/scep1/tls/pkiclient.exe";

  private static final String CA_CERT_FILE = "~/source/xipki/dist/xipki-cli/target/"
      + "xipki-cli-3.1.0-SNAPSHOT/xipki/setup/keycerts/myca1.der";

  private static final String challengePassword = "user1:password1";

  private static final AtomicLong index = new AtomicLong(System.currentTimeMillis());

  public static void main(String[] args) {
    //System.setProperty("javax.net.debug", "all");

    try {
      X509Cert caCert = X509Util.parseCert(
          IoUtil.read(new FileInputStream(expandPath(CA_CERT_FILE))));
      CaIdentifier tmpCaId = new CaIdentifier(CA_URL, null);
      CaCertValidator caCertValidator = new CaCertValidator.PreprovisionedCaCertValidator(caCert);
      ScepClient client = new ScepClient(tmpCaId, caCertValidator);

      client.init();

      // Self-Signed Identity Certificate
      MyKeypair keypair = generateRsaKeypair();
      CertificationRequest csr = genCsr(keypair, getSubject(), challengePassword);

      // self-signed cert must use the same subject as in CSR
      X500Name subjectDn = csr.getCertificationRequestInfo().getSubject();
      X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
          subjectDn, BigInteger.valueOf(1), new Date(),
          new Date(System.currentTimeMillis() + 24 * 3600 * 1000),
          subjectDn, keypair.getPublic());
      ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
          .build(keypair.getPrivate());
      X509Cert selfSignedCert = new X509Cert(certGenerator.build(signer));

      // Enroll certificate - RSA
      EnrolmentResponse resp = client.scepEnrol(csr, keypair.getPrivate(),
          selfSignedCert);
      if (resp.isFailure()) {
        throw new Exception("server returned 'failure'");
      }

      if (resp.isPending()) {
        throw new Exception("server returned 'pending'");
      }

      X509Cert cert = resp.getCertificates().get(0);
      printCert("SCEP (RSA, Self-Signed Identity Cert)", cert);

      // Use the CA signed identity certificate
      X509Cert identityCert = cert;
      PrivateKey identityKey = keypair.getPrivate();

      keypair = generateRsaKeypair();
      csr = genCsr(keypair, getSubject(), challengePassword);

      // Enroll certificate - RSA
      resp = client.scepEnrol(csr, identityKey, identityCert);
      if (resp.isFailure()) {
        throw new Exception("server returned 'failure'");
      }

      if (resp.isPending()) {
        throw new Exception("server returned 'pending'");
      }

      cert = resp.getCertificates().get(0);
      printCert("SCEP (RSA, CA issued identity Cert)", cert);

      client.destroy();
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(-1);
    }
  } // method main

  private static String getSubject() {
    return "CN=SCEP-" + index.incrementAndGet() + ".myorg.org,O=myorg,C=DE";
  }

}
