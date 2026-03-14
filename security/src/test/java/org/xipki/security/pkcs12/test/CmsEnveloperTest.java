// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.JceX509Certificate;
import org.xipki.security.util.KeyUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Iterator;

/**
 * CMS EnvelopedData test class.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsEnveloperTest {

  private static final String PROVIDER_NAME = KeyUtil.tradProviderName();

  @BeforeClass
  public static void init() {
    KeyUtil.addProviders();
  }

  @Test
  public void testPassword() throws Exception {
    passwordTest(CMSEnvelopedDataGenerator.AES256_CBC,
        PasswordRecipient.PRF.HMacSHA256, "my password".toCharArray());
  }

  @Test
  public void testEeKeyAgree() throws Exception {
    char[] password = "1234".toCharArray();

    PKCS12KeyStore ks;
    try (InputStream is = Files.newInputStream(
        Paths.get("src/test/resources/pkcs12test/test-ec.p12"))) {
      ks = KeyUtil.loadPKCS12KeyStore(is, password);
    }

    Certificate reciCert = ks.getCertificate("main");
    ASN1ObjectIdentifier curve = (ASN1ObjectIdentifier)
        reciCert.getSubjectPublicKeyInfo().getAlgorithm().getParameters();

    PrivateKeyInfo reciPrivKeyInfo = ks.getKey("main");
    PrivateKey reciPrivKey = KeyUtil.getPrivateKey(reciPrivKeyInfo);

    byte[] data = Hex.decode("1234567890abcdef");

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    kpGen.initialize(new ECGenParameterSpec(curve.getId()));
    KeyPair kp = kpGen.generateKeyPair();

    JceX509Certificate jceReciCert = new JceX509Certificate(reciCert);
    edGen.addRecipientInfoGenerator(
        new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,
            kp.getPrivate(), kp.getPublic(), CMSAlgorithm.AES128_WRAP)
            .addRecipient(jceReciCert).setProvider(PROVIDER_NAME));

    CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
            .setProvider(PROVIDER_NAME).build());

    RecipientInformationStore recipients = ed.getRecipientInfos();

    RecipientId rid = new JceKeyAgreeRecipientId(jceReciCert);

    RecipientInformation recipient = recipients.get(rid);
    byte[] recData = recipient.getContent(
        new JceKeyAgreeEnvelopedRecipient(reciPrivKey).setProvider(
            KeyUtil.tradProviderName()));
    Assert.assertArrayEquals(recData, data);
  }

  @Test
  public void testAesGcm() throws CMSException {
    SecretKey kek = new SecretKeySpec(new byte[16], "AES");
    byte[] data = Hex.decode("1234567890abcdef");
    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    byte[] kekId = new byte[]{1, 2, 3, 4, 5};

    edGen.addRecipientInfoGenerator(
        new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(PROVIDER_NAME));

    CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
            .setProvider(PROVIDER_NAME).build());

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    RecipientInformation recipient = it.next();

    byte[] recData = recipient.getContent(
        new JceKEKEnvelopedRecipient(kek).setKeySizeValidation(true)
            .setProvider(PROVIDER_NAME));
    Assert.assertArrayEquals(recData, data);
  }

  @Test
  public void testRsaOaep() throws Exception {
    HashAlgo hashAlgo = HashAlgo.SHA256;
    PKCS12KeyStore ks;
    char[] password = "CHANGEIT".toCharArray();
    try (InputStream is = Files.newInputStream(
        Paths.get("src/test/resources/pkcs12test/test1-enc.p12"))) {
      ks = KeyUtil.loadPKCS12KeyStore(is, password);
    }

    Certificate reciCert = ks.getCertificate("main");
    PrivateKey reciKey = KeyUtil.getPrivateKey(ks.getKey("main"));

    byte[] data = Hex.decode("1234567890abcdef");

    RSAESOAEPparams rsaOaepParams = new RSAESOAEPparams(
        hashAlgo.algorithmIdentifier(),
        RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION,
        RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM);

    AlgorithmIdentifier oaepAlgId = new AlgorithmIdentifier(
        OIDs.Algo.id_RSAES_OAEP, rsaOaepParams);

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    JceX509Certificate jceReciCert = new JceX509Certificate(reciCert);

    edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
        jceReciCert, oaepAlgId).setProvider(PROVIDER_NAME));

    CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
            .setProvider(PROVIDER_NAME).build());

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    RecipientInformation recipient = it.next();

    byte[] recData = recipient.getContent(
        new JceKeyTransEnvelopedRecipient(reciKey).setProvider(PROVIDER_NAME));
    Assert.assertArrayEquals(recData, data);
  }

  private void passwordTest(String algorithm, PasswordRecipient.PRF prf, char[] password)
      throws Exception {
    byte[] data = Hex.decode("1234567890abcdef");
    byte[] salt = new byte[20];
    int iterationCOunt = 10000;

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    edGen.addRecipientInfoGenerator(
        new JcePasswordRecipientInfoGenerator(
            new ASN1ObjectIdentifier(algorithm), password)
            .setPRF(prf).setSaltAndIterationCount(salt, iterationCOunt));

    CMSEnvelopedData ed0 = edGen.generate(
        new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build());

    EnvelopedData ed1 = (EnvelopedData) ed0.toASN1Structure().getContent();
    ContentInfo ci = new ContentInfo(OIDs.CMS.envelopedData, ed1);
    CMSEnvelopedData ed = new CMSEnvelopedData(ci);

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    PasswordRecipientInformation recipient = (PasswordRecipientInformation) it.next();

    byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient(password));
    Assert.assertArrayEquals(recData, data);
  }

}
