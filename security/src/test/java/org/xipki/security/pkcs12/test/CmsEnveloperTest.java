// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcPasswordRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.KeyUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * CMS EnvelopedData test class.
 *
 * @author Lijun Liao (xipki)
 */

public class CmsEnveloperTest {

  @BeforeClass
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void testPassword() throws Exception {
    passwordTest(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA256, "my password".toCharArray());
  }

  @Test
  public void testEeKeyAgree() throws Exception {
    KeyStore ks = KeyUtil.getInKeyStore("PKCS12");
    char[] password = "1234".toCharArray();
    try (InputStream is = Files.newInputStream(Paths.get("src/test/resources/pkcs12test/test-ec.p12"))) {
      ks.load(is, password);
    }

    X509Certificate reciCert = (X509Certificate) ks.getCertificate("main");
    PrivateKey reciPrivKey = (PrivateKey) ks.getKey("main", password);

    final String bc = "BC";
    byte[] data = Hex.decode("1234567890abcdef");

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    KeyPair kp = kpGen.generateKeyPair();
    edGen.addRecipientInfoGenerator(
        new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,
        kp.getPrivate(), kp.getPublic(),
        CMSAlgorithm.AES128_WRAP).addRecipient(reciCert).setProvider(bc));

    CMSEnvelopedData ed = edGen.generate(
        new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(bc).build());

    RecipientInformationStore recipients = ed.getRecipientInfos();

    RecipientId rid = new JceKeyAgreeRecipientId(reciCert);

    RecipientInformation recipient = recipients.get(rid);
    byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciPrivKey).setProvider(bc));
    Assert.assertArrayEquals(recData, data);
  }

  @Test
  public void testAesGcm() throws CMSException {
    SecretKey kek = new SecretKeySpec(new byte[16], "AES");
    byte[] data = Hex.decode("1234567890abcdef");
    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    byte[] kekId = new byte[]{1, 2, 3, 4, 5};

    edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider("BC"));

    CMSEnvelopedData ed = edGen.generate(
        new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider("BC").build());

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    RecipientInformation recipient = it.next();

    byte[] recData = recipient.getContent(
        new JceKEKEnvelopedRecipient(kek).setKeySizeValidation(true).setProvider("BC"));
    Assert.assertArrayEquals(recData, data);
  }

  @Test
  public void testRsaOaep() throws Exception {
    HashAlgo hashAlgo = HashAlgo.SHA256;
    KeyStore ks = KeyUtil.getInKeyStore("PKCS12");
    char[] password = "1234".toCharArray();
    try (InputStream is = Files.newInputStream(Paths.get("src/test/resources/pkcs12test/test1.p12"))) {
      ks.load(is, password);
    }

    X509Certificate reciCert = (X509Certificate) ks.getCertificate("main");
    PrivateKey reciKey = (PrivateKey) ks.getKey("main", password);

    byte[] data = Hex.decode("1234567890abcdef");

    RSAESOAEPparams rsaOaepParams = new RSAESOAEPparams(
        hashAlgo.getAlgorithmIdentifier(),
        RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION,
        RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM);

    AlgorithmIdentifier oaepAlgId = new AlgorithmIdentifier(
        PKCSObjectIdentifiers.id_RSAES_OAEP, rsaOaepParams);

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    final String bc = "BC";
    edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(reciCert, oaepAlgId).setProvider(bc));

    CMSEnvelopedData ed = edGen.generate(
        new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(bc).build());

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    RecipientInformation recipient = it.next();

    byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(reciKey).setProvider(bc));
    Assert.assertArrayEquals(recData, data);
  }

  private void passwordTest(String algorithm, PasswordRecipient.PRF prf, char[] password)
      throws Exception {
    byte[] data = Hex.decode("1234567890abcdef");
    byte[] salt = new byte[20];
    int iterationCOunt = 10000;

    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

    edGen.addRecipientInfoGenerator(
        new BcPasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), password)
            .setPRF(prf).setSaltAndIterationCount(salt, iterationCOunt));

    CMSEnvelopedData ed0 = edGen.generate(
        new CMSProcessableByteArray(data),
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build());

    EnvelopedData ed1 = (EnvelopedData) ed0.toASN1Structure().getContent();
    ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.envelopedData, ed1);
    CMSEnvelopedData ed = new CMSEnvelopedData(ci);

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    PasswordRecipientInformation recipient = (PasswordRecipientInformation) it.next();

    byte[] recData = recipient.getContent(new BcPasswordEnvelopedRecipient(password));
    Assert.assertArrayEquals(recData, data);
  }

}
