// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.serveremulator.ScepControl;
import org.xipki.scep.serveremulator.ScepServer;
import org.xipki.scep.serveremulator.ScepServerContainer;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.AuthorityCertStore;
import org.xipki.pkix.scep.message.CaCaps;
import org.xipki.pkix.scep.transaction.CaCapability;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.util.http.DefaultCurl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.List;

/**
 * Anchor of all CA tests.
 *
 * @author Lijun Liao (xipki)
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

  protected boolean isWithSeparateRaKeys() {
    return false;
  }

  protected boolean sendSignerCert() {
    return true;
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
    caCaps.addCapabilities(CaCapability.DES3, CaCapability.AES,
        CaCapability.SHA1, CaCapability.SHA256,
        CaCapability.POSTPKIOperation, CaCapability.SCEPStandard);
    return caCaps;
  }

  @Before
  public synchronized void startScepServer() throws Exception {
    if (scepServerContainer == null) {
      CaCaps caCaps = getExpectedCaCaps();

      ScepControl control = new ScepControl(isSendCaCert(), isPendingCert(),
          sendSignerCert(), secret);

      this.scepServer = new ScepServer("scep", caCaps, isWithRa(),
          isWithNextCa(), isGenerateCrl(), control);
      this.scepServer.setSeparateRaKeys(isWithSeparateRaKeys());
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
    KeyPairGenerator kpGen = CryptoApiFactory.get().newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    doTest(kpGen.generateKeyPair());
  }

  private void doTest(KeyPair keypair) throws Exception {
    CaIdentifier caId = new CaIdentifier("http://localhost:" + port + "/scep/pkiclient.exe", null);

    CaCertValidator caCertValidator =
        new CaCertValidator.PreprovisionedCaCertValidator(scepServer.caCert());

    ScepClient client = new ScepClient(caId, caCertValidator, new DefaultCurl());

    client.refresh();

    CaCaps expCaCaps = getExpectedCaCaps();

    // CACaps
    CaCaps caCaps = client.caCaps();
    Assert.assertEquals("CACaps", expCaCaps, caCaps);

    // CA certificate
    X509Cert expCaCert = scepServer.caCert();
    X509Cert caCert = client.authorityCertStore().caCert();
    if (!expCaCert.equals(caCert)) {
      Assert.fail("Configured and received CA certificate not the same");
    }

    boolean withRa = isWithRa();
    // RA
    if (withRa) {
      X509Cert raSigCert = client.authorityCertStore().signatureCert();
      X509Cert raEncCert = client.authorityCertStore().encryptionCert();
      Assert.assertEquals("RA signature certificate", scepServer.raCert(), raSigCert);
      Assert.assertEquals("RA encryption certificate", scepServer.raEncCert(), raEncCert);
    }

    // getNextCA
    if (isWithNextCa()) {
      AuthorityCertStore nextCa = client.scepNextCaCert();

      X509Cert expNextCaCert = scepServer.nextCaCert();
      X509Cert nextCaCert = nextCa.caCert();
      if (!expNextCaCert.equals(nextCaCert)) {
        Assert.fail("Configured and received next CA certificate not the same");
      }

      if (withRa) {
        X509Cert expNextRaCert = scepServer.nextRaCert();
        X509Cert nextRaSigCert = nextCa.signatureCert();
        X509Cert nextRaEncCert = nextCa.encryptionCert();
        Assert.assertEquals("Next RA certificate", nextRaSigCert, nextRaEncCert);

        if (!expNextRaCert.equals(nextRaSigCert)) {
          Assert.fail("Configured and received next RA certificate not the same");
        }
      }
    }

    // enroll
    X509Cert selfSignedCert;
    X509Cert enroledCert;
    X500Name issuerName = caCert.subject();
    PrivateKey privKey;

    CertificationRequest csr;
    CertificationRequest p10Req;
    {
      privKey = keypair.getPrivate();
      SubjectPublicKeyInfo subjectPublicKeyInfo =
          MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
      X500Name subject = new X500Name("CN=EE1, OU=emulator, O=myorg.org, C=DE");

      // try with valid secret
      p10Req = MyUtil.generateRequest(privKey, subjectPublicKeyInfo, subject, secret, null);

      selfSignedCert = MyUtil.generateSelfsignedCert(p10Req, privKey);

      EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req, privKey, selfSignedCert);

      List<X509Cert> certs = enrolResp.certificates();
      Assert.assertFalse("number of received certificates", certs.isEmpty());
      X509Cert cert = certs.get(0);
      Assert.assertNotNull("enroled certificate", cert);
      enroledCert = cert;

      // try :: self-signed certificate's subject different from the one of CSR
      p10Req = MyUtil.generateRequest(privKey, subjectPublicKeyInfo, subject, secret, null);

      selfSignedCert = MyUtil.generateSelfsignedCert(new X500Name("CN=dummy"),
          p10Req.getSubjectPKInfo(), privKey);
      enrolResp = client.scepPkcsReq(p10Req, privKey, selfSignedCert);

      PkiStatus status = enrolResp.pkcsRep().pkiStatus();
      Assert.assertEquals("PkiStatus with invalid secret", PkiStatus.FAILURE, status);
    }

    // certPoll
    EnrolmentResponse enrolResp = client.scepCertPoll(privKey, selfSignedCert, p10Req, issuerName);

    List<X509Cert> certs = enrolResp.certificates();
    Assert.assertFalse("number of received certificates", certs.isEmpty());
    Assert.assertNotNull("enrolled certificate", certs.get(0));

    // getCert
    certs = client.scepGetCert(privKey, selfSignedCert, issuerName, enroledCert.serialNumber());
    Assert.assertFalse("number of received certificates", certs.isEmpty());
    Assert.assertNotNull("received certificate", certs.get(0));

    // getCRL
    CertificateList crl = client.scepGetCrl(privKey, enroledCert,
        issuerName, enroledCert.serialNumber());
    Assert.assertNotNull("received CRL", crl);

    // getNextCA
    AuthorityCertStore nextCa = client.scepNextCaCert();
    Assert.assertNotNull("nextCa", nextCa);
  } // method test

  private CaCaps getExpectedCaCaps() {
    CaCaps caCaps = getDefaultCaCaps();
    CaCapability[] excludedCaCaps = getExcludedCaCaps();
    if (excludedCaCaps != null) {
      caCaps.removeCapabilities(excludedCaCaps);
    }

    if (isWithNextCa()) {
      if (!caCaps.supportsGetNextCACert()) {
        caCaps.addCapabilities(CaCapability.GetNextCACert);
      }
    } else {
      caCaps.removeCapabilities(CaCapability.GetNextCACert);
    }
    return caCaps;
  } // method getExpectedCaCaps

}
