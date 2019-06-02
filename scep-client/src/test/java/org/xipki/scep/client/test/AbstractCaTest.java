/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.scep.client.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.PreprovisionedCaCertValidator;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.message.AuthorityCertStore;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.serveremulator.ScepControl;
import org.xipki.scep.serveremulator.ScepServer;
import org.xipki.scep.serveremulator.ScepServerContainer;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public abstract class AbstractCaTest {

  private final String secret = "preshared-secret";

  private final int port = 8081;

  private ScepServerContainer scepServerContainer;

  private ScepServer scepServer;

  protected abstract CaCapability[] getExcludedCaCaps();

  protected boolean isWithRa() {
    return true;
  }

  protected boolean sendSignerCert() {
    return true;
  }

  protected boolean useInsecureAlgorithms() {
    return false;
  }

  protected boolean isWithNextCa() {
    return true;
  }

  protected boolean isSendCaCert() {
    return false;
  }

  protected boolean isPendingCert() {
    return false;
  }

  protected boolean isGenerateCrl() {
    return true;
  }

  @Before
  public void init() {
  }

  protected CaCaps getDefaultCaCaps() {
    final CaCaps caCaps = new CaCaps();
    caCaps.addCapabilities(CaCapability.DES3, CaCapability.AES, CaCapability.SHA1,
        CaCapability.SHA256, CaCapability.POSTPKIOperation);
    return caCaps;
  }

  @Before
  public synchronized void startScepServer() throws Exception {
    if (scepServerContainer == null) {
      CaCaps caCaps = getExpectedCaCaps();

      ScepControl control = new ScepControl(isSendCaCert(), isPendingCert(), sendSignerCert(),
          useInsecureAlgorithms(), secret);

      this.scepServer = new ScepServer("scep", caCaps, isWithRa(), isWithNextCa(), isGenerateCrl(),
          control);
      this.scepServerContainer = new ScepServerContainer(port, scepServer);
    }

    this.scepServerContainer.start();
  }

  @After
  public synchronized void stopScepServer() throws Exception {
    if (this.scepServerContainer != null) {
      this.scepServerContainer.stop();
    }
  }

  @Test
  public void test() throws Exception {
    CaIdentifier caId = new CaIdentifier("http://localhost:" + port + "/scep/pkiclient.exe", null);
    CaCertValidator caCertValidator = new PreprovisionedCaCertValidator(
            ScepUtil.toX509Cert(scepServer.getCaCert()));
    ScepClient client = new ScepClient(caId, caCertValidator);
    client.setUseInsecureAlgorithms(useInsecureAlgorithms());

    client.refresh();

    CaCaps expCaCaps = getExpectedCaCaps();

    // CACaps
    CaCaps caCaps = client.getCaCaps();
    Assert.assertEquals("CACaps", expCaCaps, caCaps);

    // CA certificate
    Certificate expCaCert = scepServer.getCaCert();
    X509Certificate caCert = client.getAuthorityCertStore().getCaCert();
    if (!equals(expCaCert, caCert)) {
      Assert.fail("Configured and received CA certificate not the same");
    }

    boolean withRa = isWithRa();
    // RA
    if (withRa) {
      Certificate expRaCert = scepServer.getRaCert();
      X509Certificate raSigCert = client.getAuthorityCertStore().getSignatureCert();
      X509Certificate raEncCert = client.getAuthorityCertStore().getEncryptionCert();
      Assert.assertEquals("RA certificate", raSigCert, raEncCert);

      if (!equals(expRaCert, raSigCert)) {
        Assert.fail("Configured and received RA certificate not the same");
      }
    }

    // getNextCA
    if (isWithNextCa()) {
      AuthorityCertStore nextCa = client.scepNextCaCert();

      Certificate expNextCaCert = scepServer.getNextCaCert();
      X509Certificate nextCaCert = nextCa.getCaCert();
      if (!equals(expNextCaCert, nextCaCert)) {
        Assert.fail("Configured and received next CA certificate not the same");
      }

      if (withRa) {
        Certificate expNextRaCert = scepServer.getNextRaCert();
        X509Certificate nextRaSigCert = nextCa.getSignatureCert();
        X509Certificate nextRaEncCert = nextCa.getEncryptionCert();
        Assert.assertEquals("Next RA certificate", nextRaSigCert, nextRaEncCert);

        if (!equals(expNextRaCert, nextRaSigCert)) {
          Assert.fail("Configured and received next RA certificate not the same");
        }
      }
    }

    // enroll
    CertificationRequest csr;

    X509Certificate selfSignedCert;
    X509Certificate enroledCert;
    X500Name issuerName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
    PrivateKey privKey;

    {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
      kpGen.initialize(2048);
      KeyPair keypair = kpGen.generateKeyPair();
      privKey = keypair.getPrivate();
      SubjectPublicKeyInfo subjectPublicKeyInfo = ScepUtil.createSubjectPublicKeyInfo(
              keypair.getPublic());
      X500Name subject = new X500Name("CN=EE1, OU=emulator, O=xipki.org, C=DE");

      // first try without secret
      PKCS10CertificationRequest p10Req = ScepUtil.generateRequest(privKey, subjectPublicKeyInfo,
          subject, null, null);
      csr = p10Req.toASN1Structure();

      selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
      EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey,
          selfSignedCert);
      PkiStatus status = enrolResp.getPkcsRep().getPkiStatus();
      Assert.assertEquals("PkiStatus without secret", PkiStatus.FAILURE, status);

      // then try invalid secret
      p10Req = ScepUtil.generateRequest(privKey, subjectPublicKeyInfo, subject,
          "invalid-" + secret, null);
      csr = p10Req.toASN1Structure();

      selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
      enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);
      status = enrolResp.getPkcsRep().getPkiStatus();
      Assert.assertEquals("PkiStatus with invalid secret", PkiStatus.FAILURE, status);

      // try with valid secret
      p10Req = ScepUtil.generateRequest(privKey, subjectPublicKeyInfo, subject, secret, null);
      csr = p10Req.toASN1Structure();

      selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
      enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);

      List<X509Certificate> certs = enrolResp.getCertificates();
      Assert.assertTrue("number of received certificates", certs.size() > 0);
      X509Certificate cert = certs.get(0);
      Assert.assertNotNull("enroled certificate", cert);
      enroledCert = cert;

      // try :: self-signed certificate's subject different from the one of CSR
      p10Req = ScepUtil.generateRequest(privKey, subjectPublicKeyInfo, subject, secret, null);
      csr = p10Req.toASN1Structure();

      selfSignedCert = ScepUtil.generateSelfsignedCert(new X500Name("CN=dummy"),
          csr.getCertificationRequestInfo().getSubjectPublicKeyInfo(), privKey);
      enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);
      status = enrolResp.getPkcsRep().getPkiStatus();
      Assert.assertEquals("PkiStatus with invalid secret", PkiStatus.FAILURE, status);
    }

    // certPoll
    EnrolmentResponse enrolResp = client.scepCertPoll(privKey, selfSignedCert, csr, issuerName);

    List<X509Certificate> certs = enrolResp.getCertificates();
    Assert.assertTrue("number of received certificates", certs.size() > 0);
    X509Certificate cert = certs.get(0);
    Assert.assertNotNull("enrolled certificate", cert);

    // getCert
    certs = client.scepGetCert(privKey, selfSignedCert, issuerName, enroledCert.getSerialNumber());
    Assert.assertTrue("number of received certificates", certs.size() > 0);
    cert = certs.get(0);
    Assert.assertNotNull("received certificate", cert);

    // getCRL
    X509CRL crl = client.scepGetCrl(privKey, enroledCert, issuerName,
        enroledCert.getSerialNumber());
    Assert.assertNotNull("received CRL", crl);

    // getNextCA
    AuthorityCertStore nextCa = client.scepNextCaCert();
    Assert.assertNotNull("nextCa", nextCa);
  }

  private CaCaps getExpectedCaCaps() {
    CaCaps caCaps = getDefaultCaCaps();
    CaCapability[] excludedCaCaps = getExcludedCaCaps();
    if (excludedCaCaps != null) {
      caCaps.removeCapabilities(excludedCaCaps);
    }

    if (isWithNextCa()) {
      if (!caCaps.containsCapability(CaCapability.GetNextCACert)) {
        caCaps.addCapabilities(CaCapability.GetNextCACert);
      }
    } else {
      caCaps.removeCapabilities(CaCapability.GetNextCACert);
    }
    return caCaps;
  }

  private boolean equals(Certificate bcCert, X509Certificate cert)
      throws CertificateException, IOException {
    return Arrays.equals(cert.getEncoded(), bcCert.getEncoded());
  }

}
