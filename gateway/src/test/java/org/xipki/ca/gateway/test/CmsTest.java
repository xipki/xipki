// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.JceX509Certificate;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.KeyUtil;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Iterator;

/**
 * CMS envelope test. Simulate the process to encrypt / decrypt key material
 * in CMP.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsTest {

  private static final SecureRandom random = new SecureRandom();

  @Test
  public void ecdheTest() throws Exception {
    doTest("P256/tls-c1.p12");
  }

  @Test
  public void rsaTest() throws Exception {
    doTest("RSA2048/tls-c1.p12");
  }

  private void doTest(String p12File) throws Exception {
    KeyUtil.addProviders();

    PKCS12KeyStore keyStore;
    try (InputStream is = CmsTest.class.getClassLoader().getResourceAsStream(p12File)) {
      keyStore = KeyUtil.loadPKCS12KeyStore(is, "CHANGEIT".toCharArray());
    }

    PrivateKey privateKey = KeyUtil.getPrivateKey(keyStore.getKey("main"));
    X509Cert x509Cert = new X509Cert(keyStore.getCertificate("main"));
    X509Certificate jceCert = new JceX509Certificate(x509Cert.getCert());

    RecipientInfoGenerator recipient;
    if (privateKey instanceof RSAPrivateKey) {
      // Use RSA/OAEP instead RSA/PKCS1
      AlgorithmIdentifier hashAlgId = HashAlgo.SHA256.algorithmIdentifier();
      AlgorithmIdentifier mgfAlgId =
          new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId);
      AlgorithmIdentifier oaepAlgId = new AlgorithmIdentifier( OIDs.Algo.id_RSAES_OAEP,
          new RSAESOAEPparams(hashAlgId, mgfAlgId, RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM));
      recipient = new JceKeyTransRecipientInfoGenerator(jceCert, oaepAlgId);
    } else if (privateKey instanceof ECPrivateKey) {
      // We use ECDHE with AES Key Wrap (standard for EC-based CMS)
      KeySpec keySpec = KeySpec.ofPublicKey(x509Cert.subjectPublicKeyInfo());
      KeyPair keyPair = KeyUtil.generateKeyPair(keySpec, random);
      recipient = new JceKeyAgreeRecipientInfoGenerator(
          CMSAlgorithm.ECDH_SHA256KDF, // Key Agreement Algorithm
          keyPair.getPrivate(), keyPair.getPublic(),
          CMSAlgorithm.AES256_WRAP // Algorithm to wrap the content key
      ).setSecureRandom(random).addRecipient(jceCert)
          .setProvider(KeyUtil.tradProviderName());
    } else {
      throw new IllegalArgumentException(
          "unsupported key class " + privateKey.getClass().getName());
    }

    // 1. Initialize the Generator
    CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();

    // 2. Add the Recipient (The person who can decrypt this)
    gen.addRecipientInfoGenerator(recipient);

    // 3. Define the Content Encryption Algorithm (e.g., AES-256 GCM)
    // This is the symmetric key used to encrypt the actual payload
    JceCMSContentEncryptorBuilder encryptorBuilder =
        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)
            .setProvider(KeyUtil.tradProviderName());

    // 4. Generate the EnvelopedData
    byte[] data = new byte[100];
    CMSProcessableByteArray msg = new CMSProcessableByteArray(data);
    CMSEnvelopedData envelopedData = gen.generate(msg, encryptorBuilder.build());
    decrypt(envelopedData, privateKey);
  }

  private static byte[] decrypt(CMSEnvelopedData envelopedData, PrivateKey decKey)
      throws GeneralSecurityException {
    try {
      ContentInfo ci = envelopedData.toASN1Structure();
      CMSEnvelopedData ed = new CMSEnvelopedData(ci);

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      RecipientInformation ri = it.next();

      Recipient recipient;
      if (ri instanceof KeyAgreeRecipientInformation) {
        recipient = new JceKeyAgreeEnvelopedRecipient(decKey)
            .setProvider(KeyUtil.tradProviderName());
      } else if (ri instanceof KeyTransRecipientInformation) {
        recipient = new JceKeyTransEnvelopedRecipient(decKey)
            .setProvider(KeyUtil.tradProviderName());
      } else {
        throw new GeneralSecurityException(
            "unsupported RecipientInformation " + ri.getClass().getName());
      }

      return ri.getContent(recipient);
    } catch (CMSException ex) {
      throw new GeneralSecurityException(ex.getMessage(), ex);
    }
  }

}
