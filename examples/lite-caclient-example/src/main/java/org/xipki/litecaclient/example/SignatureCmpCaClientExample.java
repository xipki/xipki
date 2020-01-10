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

import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.litecaclient.CmpCaClient;
import org.xipki.litecaclient.KeyAndCert;
import org.xipki.litecaclient.SdkUtil;
import org.xipki.litecaclient.SignatureCmpCaClient;

/**
 * Example to use {@link CmpCaClient}.
 * @author Lijun Liao
 */

public class SignatureCmpCaClientExample extends CaClientExample {

  //private static final String URL_PREFIX = "http://localhost:8080/ca";

  private static final String URL_PREFIX = "https://localhost:8443/ca";

  private static final String CMP_URL = URL_PREFIX + "/cmp/myca";

  private static final String KEYCERT_DIR =  "target/tlskeys";

  private static final String REQUESTOR_KEYSTORE_FILE = KEYCERT_DIR + "/client/tls-client.p12";

  private static final String REQUESTOR_KEYSTORE_PASSWORD = "1234";

  private static final String RESPONDER_CERT_FILE = KEYCERT_DIR + "/server/tls-server-cert.der";

  private static final String HASH_ALGO = "SHA256";

  private static final String CERT_PROFILE = "tls";

  private static final AtomicLong index = new AtomicLong(System.currentTimeMillis());

  private static final boolean profileAndKeyTypeInUri = true;

  public static void main(String[] args) {
    //System.setProperty("javax.net.debug", "all");

    if (!new File(KEYCERT_DIR).exists()) {
      System.err.println("Please call \"mvn generate-resources\" first.");
      return;
    }

    Security.addProvider(new BouncyCastleProvider());

    try {
      KeyStore ks = KeyStore.getInstance("PKCS12");

      char[] password = REQUESTOR_KEYSTORE_PASSWORD.toCharArray();
      InputStream ksStream = Files.newInputStream(Paths.get(expandPath(REQUESTOR_KEYSTORE_FILE)));
      ks.load(ksStream, password);
      ksStream.close();

      Enumeration<String> aliases = ks.aliases();

      String alias = null;
      while (aliases.hasMoreElements()) {
        String tmp = aliases.nextElement();
        if (ks.isKeyEntry(tmp)) {
          alias = tmp;
          break;
        }
      }

      PrivateKey requestorKey = (PrivateKey) ks.getKey(alias, password);
      X509Certificate requestorCert = (X509Certificate) ks.getCertificate(alias);

      X509Certificate responderCert = SdkUtil.parseCert(new File(expandPath(RESPONDER_CERT_FILE)));
      CmpCaClient client = new SignatureCmpCaClient(CMP_URL, null, requestorKey, requestorCert,
          responderCert, HASH_ALGO);

      client.init();
      X509Certificate caCert = client.getCaCert();
      // CHECKSTYLE:SKIP
      X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

      // retrieve CA certificate
      printCert("===== CA Certificate =====", client.getCaCert());

      // Enroll certificate via CRMF - (CA generate keypair)
      KeyAndCert[] keyAndCerts =
          client.enrollCertsViaCrmfCaGenKeypair(new String[] {CERT_PROFILE, CERT_PROFILE},
          new String[]{getSubject(), getSubject()}, profileAndKeyTypeInUri);
      for (int i = 0; i < keyAndCerts.length; i++) {
        printKeyAndCert("===== Enroll via CRMF (CMP, CA generate keypair) =====", keyAndCerts[i]);
      }

      // Enroll certificate via CSR - RSA
      MyKeypair kp = generateRsaKeypair();
      CertificationRequest csr = genCsr(kp, getSubject());
      X509Certificate cert = client.enrollCertViaCsr(CERT_PROFILE, csr, profileAndKeyTypeInUri);
      printCert("===== Enroll RSA via CSR (CMP) =====", cert);

      // Enroll certificate via CSR - EC
      kp = generateEcKeypair();
      csr = genCsr(kp, getSubject());
      cert = client.enrollCertViaCsr(CERT_PROFILE, csr, profileAndKeyTypeInUri);
      printCert("===== Enroll Enroll EC via CSR (CMP) =====", cert);

      // Enroll certificate via CSR - DSA
      kp = generateDsaKeypair();
      csr = genCsr(kp, getSubject());
      cert = client.enrollCertViaCsr(CERT_PROFILE, csr, profileAndKeyTypeInUri);
      printCert("===== Enroll DSA via CSR (CMP) =====", cert);

      // Enroll certificate via CRMF - RSA
      kp = generateRsaKeypair();
      cert = client.enrollCertViaCrmf(CERT_PROFILE, kp.getPrivate(), kp.getPublic(), getSubject(),
          profileAndKeyTypeInUri);
      printCert("===== Enroll Enroll RSA via CRMF (CMP) =====", cert);

      // Update certificate via CRMF - RSA
      cert = client.updateCertViaCrmf(kp.getPrivate(), issuer, cert.getSerialNumber());
      printCert("===== Update RSA via CRMF (CMP) =====", cert);

      // Update certificate via CRMF - RSA (CA generate key pair)
      KeyAndCert keyAndCert = client.updateCertViaCrmfCaGenKeypair(issuer, cert.getSerialNumber(),
          profileAndKeyTypeInUri);
      printKeyAndCert("===== Update via CRMF (CMP, CA generate keypair) =====", keyAndCert);

      // Enroll certificate via CRMF - EC
      kp = generateEcKeypair();
      MyKeypair kp2 = generateEcKeypair();
      X509Certificate[] certs = client.enrollCertsViaCrmf(new String[] {CERT_PROFILE, CERT_PROFILE},
          new PrivateKey[] {kp.getPrivate(), kp2.getPrivate()},
          new SubjectPublicKeyInfo[] {kp.getPublic(), kp2.getPublic()},
          new String[]{getSubject(), getSubject()}, profileAndKeyTypeInUri);
      for (int i = 0; i < certs.length; i++) {
        printCert("===== Enroll EC via CRMF (CMP) =====", certs[i]);
      }

      // Update certificate via CRMF - EC
      certs = client.updateCertsViaCrmf(new PrivateKey[] {kp.getPrivate(), kp2.getPrivate()},
          issuer, new BigInteger[] {certs[0].getSerialNumber(), certs[1].getSerialNumber()});
      for (int i = 0; i < certs.length; i++) {
        printCert("===== Update EC via CRMF (CMP) =====", certs[i]);
      }

      // Enroll certificate via CRMF - DSA
      kp = generateDsaKeypair();
      cert = client.enrollCertViaCrmf(CERT_PROFILE, kp.getPrivate(), kp.getPublic(), getSubject(),
          profileAndKeyTypeInUri);
      printCert("===== Enroll DSA via CRMF (CMP) =====", cert);

      // Update certificate via CRMF - DSA
      cert = client.updateCertViaCrmf(kp.getPrivate(), issuer, cert.getSerialNumber());
      printCert("===== Update DSA via CRMF (CMP) =====", cert);

      BigInteger serialNumber = cert.getSerialNumber();
      // Suspend certificate
      boolean flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.certificateHold));
      if (flag) {
        System.out.println("(CMP) suspended certificate");
      } else {
        System.err.println("(CMP) suspending certificate failed");
      }

      // Unsuspend certificate
      flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.removeFromCRL));
      if (flag) {
        System.out.println("(CMP) unsuspended certificate");
      } else {
        System.err.println("(CMP) unsuspending certificate failed");
      }

      // Revoke certificate
      flag = client.revokeCert(serialNumber, CRLReason.lookup(CRLReason.keyCompromise));
      if (flag) {
        System.out.println("(CMP) revoked certificate");
      } else {
        System.err.println("(CMP) revoking certificate failed");
      }

      client.close();
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(-1);
    }
  } // method main

  private static String getSubject() {
    return "CN=CMP-" + index.incrementAndGet() + ".xipki.org,O=xipki,C=DE";
  }

}
