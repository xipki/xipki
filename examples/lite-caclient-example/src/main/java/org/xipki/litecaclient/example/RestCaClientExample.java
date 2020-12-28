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

package org.xipki.litecaclient.example;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.CRLReason;
import org.xipki.litecaclient.RestCaClient;

/**
 * Example to use {@link RestCaClient}.
 *
 * @author Lijun Liao
 */

public class RestCaClientExample extends CaClientExample {

  private static final String CA_URL = "https://localhost:8443/ca/rest/myca";

  private static final String USER = "user1";

  private static final String PASSWORD = "password1";

  private static final String CERT_PROFILE = "tls";

  private static final AtomicLong index = new AtomicLong(System.currentTimeMillis());

  public static void main(String[] args) {
    //System.setProperty("javax.net.debug", "all");
    try {
      RestCaClient client = new RestCaClient(CA_URL, USER, PASSWORD);

      client.init();

      // retrieve CA certificate
      printCert("===== CA Certificate (REST) =====", client.getCaCert());

      // Enroll certificate - RSA
      MyKeypair kp = generateRsaKeypair();
      CertificationRequest csr = genCsr(kp, getSubject());
      X509Certificate cert = client.requestCert(CERT_PROFILE, csr);
      printCert("===== RSA (REST) =====", cert);

      // Enroll certificate - EC
      kp = generateEcKeypair();
      csr = genCsr(kp, getSubject());
      cert = client.requestCert(CERT_PROFILE, csr);
      printCert("===== EC (REST) =====", cert);

      // Enroll certificate - DSA
      kp = generateDsaKeypair();
      csr = genCsr(kp, getSubject());
      cert = client.requestCert(CERT_PROFILE, csr);
      printCert("===== DSA =====", cert);

      BigInteger serialNumber = cert.getSerialNumber();
      // Suspend certificate
      boolean flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.certificateHold));
      if (flag) {
        System.out.println("(REST) suspended certificate");
      } else {
        System.err.println("(REST) suspending certificate failed");
      }

      // Unsuspend certificate
      flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.removeFromCRL));
      if (flag) {
        System.out.println("(REST) unsuspended certificate");
      } else {
        System.err.println("(REST) unsuspending certificate failed");
      }

      // Revoke certificate
      flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.keyCompromise));
      if (flag) {
        System.out.println("(REST) revoked certificate");
      } else {
        System.err.println("(REST) revoking certificate failed");
      }

      client.close();
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(-1);
    }
  } // method main

  private static String getSubject() {
    return "CN=REST-" + index.incrementAndGet() + ".myorg.org,O=myorg,C=DE";
  }

}
