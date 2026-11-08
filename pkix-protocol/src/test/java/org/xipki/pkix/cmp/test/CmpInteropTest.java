// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp.test;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.cmp.PBMParameter;
import org.xipki.asn1.cmp.PKIMessage;
import org.xipki.asn1.crmf.CertReqMsg;
import org.xipki.asn1.crmf.CertRequest;
import org.xipki.asn1.crmf.CertTemplate;
import org.xipki.asn1.crmf.POPOSigningKey;
import org.xipki.asn1.crmf.ProofOfPossession;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.pkix.cmp.CertificateRequestMessage;
import org.xipki.pkix.cmp.ProtectedPKIMessage;

import java.math.BigInteger;

/**
 * Interoperability tests of the CMP message protection and the CRMF proof of possession against
 * BouncyCastle, in both directions.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpInteropTest {

  private static final char[] PASSWORD = "cmp-password".toCharArray();

  private static final byte[] TID = {1, 2, 3, 4, 5, 6, 7, 8};

  private static final AlgorithmIdentifier SHA256_WITH_RSA =
      AlgorithmIdentifier.ofNullParams(PkcsOIDs.sha256WithRSAEncryption);

  // ---------------- password-based MAC ----------------

  @Test
  public void testPbmacToBc() throws Exception {
    for (boolean sha256 : new boolean[]{false, true}) {
      AlgorithmIdentifier owf = AlgorithmIdentifier.ofNullParams(
          sha256 ? AlgorithmOIDs.id_sha256 : AlgorithmOIDs.id_sha1);
      AlgorithmIdentifier mac = AlgorithmIdentifier.ofNullParams(
          sha256 ? AlgorithmOIDs.id_hmacWithSHA256 : PkcsOIDs.id_hmacWithSHA1);
      PBMParameter params = new PBMParameter(new byte[16], owf, 1000, mac);

      ProtectedPKIMessage msg = newXipkiBuilder().build(params, PASSWORD);
      Assert.assertTrue(msg.hasPasswordBasedMacProtection());

      org.bouncycastle.cert.cmp.ProtectedPKIMessage bcMsg = toBc(msg.toASN1Structure());
      Assert.assertTrue("BC verify, sha256=" + sha256, bcMsg.verify(bcPkMacBuilder(), PASSWORD));
      Assert.assertFalse("BC verify wrong password",
          bcMsg.verify(bcPkMacBuilder(), "wrong".toCharArray()));

      // xipki verifies its own message
      ProtectedPKIMessage parsed = new ProtectedPKIMessage(
          PKIMessage.fromEncoded(msg.toASN1Structure().getEncoded()));
      Assert.assertTrue(parsed.verify(PASSWORD));
    }
  }

  @Test
  public void testPbmacFromBc() throws Exception {
    org.bouncycastle.cert.cmp.ProtectedPKIMessage bcMsg = newBcBuilder()
        .build(bcPkMacBuilder().build(PASSWORD));

    ProtectedPKIMessage msg = new ProtectedPKIMessage(
        PKIMessage.fromEncoded(bcMsg.toASN1Structure().getEncoded()));
    Assert.assertTrue(msg.hasPasswordBasedMacProtection());
    Assert.assertTrue("verify", msg.verify(PASSWORD));
    Assert.assertFalse("verify wrong password", msg.verify("wrong".toCharArray()));
  }

  // ---------------- signature ----------------

  @Test
  public void testSignatureToBc() throws Exception {
    TestUtil.KeyAndCert kc = TestUtil.rsa();
    ProtectedPKIMessage msg = newXipkiBuilder()
        .addCMPCertificate(kc.cert)
        .build(TestUtil.signer(kc.keyPair.getPrivate(), "SHA256withRSA", SHA256_WITH_RSA));

    org.bouncycastle.cert.cmp.ProtectedPKIMessage bcMsg = toBc(msg.toASN1Structure());
    Assert.assertFalse(bcMsg.hasPasswordBasedMacProtection());
    Assert.assertEquals(1, bcMsg.getCertificates().length);
    Assert.assertTrue("BC verify", bcMsg.verify(new JcaContentVerifierProviderBuilder()
        .setProvider(TestUtil.BC).build(kc.bcCert)));
  }

  @Test
  public void testSignatureFromBc() throws Exception {
    for (TestUtil.KeyAndCert kc : new TestUtil.KeyAndCert[]{TestUtil.rsa(), TestUtil.ec()}) {
      String alg = kc == TestUtil.rsa() ? "SHA256withRSA" : "SHA256withECDSA";
      org.bouncycastle.cert.cmp.ProtectedPKIMessage bcMsg = newBcBuilder()
          .addCMPCertificate(kc.bcCert)
          .build(new JcaContentSignerBuilder(alg).setProvider(TestUtil.BC)
              .build(kc.keyPair.getPrivate()));

      ProtectedPKIMessage msg = new ProtectedPKIMessage(
          PKIMessage.fromEncoded(bcMsg.toASN1Structure().getEncoded()));
      Assert.assertFalse(msg.hasPasswordBasedMacProtection());
      Assert.assertEquals(1, msg.toASN1Structure().getExtraCerts().size());
      Assert.assertTrue(alg, msg.verify(TestUtil.verifierProvider(kc.keyPair.getPublic(), null)));

      TestUtil.KeyAndCert other = kc == TestUtil.rsa() ? TestUtil.ec() : TestUtil.rsa();
      boolean valid;
      try {
        valid = msg.verify(TestUtil.verifierProvider(other.keyPair.getPublic(), null));
      } catch (Exception e) {
        valid = false;
      }
      Assert.assertFalse(alg + " with wrong key", valid);
    }
  }

  // ---------------- CRMF proof of possession ----------------

  @Test
  public void testPopToBc() throws Exception {
    TestUtil.KeyAndCert kc = TestUtil.rsa();
    CertTemplate template = new CertTemplate();
    template.setSubject(kc.cert.getSubject());
    template.setPublicKey(kc.cert.getSubjectPublicKeyInfo());
    CertRequest certRequest = new CertRequest(1, template, null);

    POPOSigningKey popo = CertificateRequestMessage.buildSigningKeyPop(certRequest,
        TestUtil.signer(kc.keyPair.getPrivate(), "SHA256withRSA", SHA256_WITH_RSA));
    CertReqMsg reqMsg = new CertReqMsg(certRequest, ProofOfPossession.ofSignature(popo));

    org.bouncycastle.cert.crmf.CertificateRequestMessage bcReq =
        new org.bouncycastle.cert.crmf.CertificateRequestMessage(reqMsg.getEncoded());
    Assert.assertEquals(org.bouncycastle.cert.crmf.CertificateRequestMessage.popSigningKey,
        bcReq.getProofOfPossessionType());
    Assert.assertTrue("BC verify POP", bcReq.isValidSigningKeyPOP(
        new JcaContentVerifierProviderBuilder().setProvider(TestUtil.BC)
            .build(kc.keyPair.getPublic())));

    // xipki verifies its own POP
    CertificateRequestMessage req = new CertificateRequestMessage(
        CertReqMsg.fromEncoded(reqMsg.getEncoded()));
    Assert.assertTrue(req.isValidSigningKeyPOP(
        TestUtil.verifierProvider(kc.keyPair.getPublic(), null)));
  }

  @Test
  public void testPopFromBc() throws Exception {
    TestUtil.KeyAndCert kc = TestUtil.ec();
    org.bouncycastle.cert.crmf.CertificateRequestMessage bcReq =
        new CertificateRequestMessageBuilder(BigInteger.ONE)
            .setSubject(kc.bcCert.getSubject())
            .setPublicKey(kc.bcCert.getSubjectPublicKeyInfo())
            .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(TestUtil.BC).build(kc.keyPair.getPrivate()))
            .build();

    CertificateRequestMessage req = new CertificateRequestMessage(
        CertReqMsg.fromEncoded(bcReq.getEncoded()));
    Assert.assertTrue(req.hasProofOfPossession());
    Assert.assertEquals(CertificateRequestMessage.tag_popSigningKey,
        req.getProofOfPossessionType());
    Assert.assertTrue("verify POP", req.isValidSigningKeyPOP(
        TestUtil.verifierProvider(kc.keyPair.getPublic(), null)));
    Assert.assertFalse("verify POP with wrong key", req.isValidSigningKeyPOP(
        TestUtil.verifierProvider(TestUtil.newEcKeyPair().getPublic(), null)));
  }

  // ---------------- helpers ----------------

  private static ProtectedPKIMessage.Builder newXipkiBuilder() throws Exception {
    org.xipki.asn1.x500.X500Name sender = TestUtil.rsa().cert.getSubject();
    return new ProtectedPKIMessage.Builder(
        org.xipki.asn1.x509.GeneralName.ofDirectoryName(sender),
        org.xipki.asn1.x509.GeneralName.ofDirectoryName(sender))
        .setTransactionID(TID)
        .setSenderNonce(new byte[16])
        .setBody(org.xipki.asn1.cmp.PKIBody.ofPkiconf());
  }

  private static ProtectedPKIMessageBuilder newBcBuilder() {
    GeneralName name = new GeneralName(new X500Name("CN=CMP Test"));
    return new ProtectedPKIMessageBuilder(name, name)
        .setTransactionID(TID)
        .setSenderNonce(new byte[16])
        .setBody(new PKIBody(PKIBody.TYPE_CONFIRM,
                  PKIConfirmContent.getInstance(DERNull.INSTANCE)));
  }

  private static PKMACBuilder bcPkMacBuilder() {
    return new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(TestUtil.BC));
  }

  private static org.bouncycastle.cert.cmp.ProtectedPKIMessage toBc(PKIMessage msg)
      throws Exception {
    return new org.bouncycastle.cert.cmp.ProtectedPKIMessage(
        new GeneralPKIMessage(msg.getEncoded()));
  }

}
