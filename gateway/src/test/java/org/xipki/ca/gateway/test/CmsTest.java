// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsRecipient;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.KeyUtil;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * CMS EnvelopedData test, as used for the centrally generated keys in CMP.
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
    Pkcs12KeyStore keyStore;
    try (InputStream is = CmsTest.class.getClassLoader().getResourceAsStream(p12File)) {
      keyStore = KeyUtil.loadPKCS12KeyStore(is, "CHANGEIT".toCharArray());
    }

    PrivateKey privateKey = KeyInfoUtil.getPrivateKey(keyStore.getKey("main"));
    X509Cert x509Cert = new X509Cert(keyStore.getCertificate("main"));

    CmsEnvelopedData.Builder builder = new CmsEnvelopedData.Builder().setSecureRandom(random);
    if (privateKey instanceof RSAPrivateKey) {
      // Use RSA/OAEP instead RSA/PKCS1
      AlgorithmIdentifier hashAlgId = HashAlgo.SHA256.algorithmIdentifier();
      AlgorithmIdentifier mgfAlgId =
          AlgorithmIdentifier.build(PkcsOIDs.id_mgf1, hashAlgId);
      AlgorithmIdentifier oaepAlgId = AlgorithmIdentifier.build(AlgorithmOIDs.id_RSAES_OAEP,
          new RSAESOAEPParams(hashAlgId, mgfAlgId, RSAESOAEPParams.DEFAULT_P_SOURCE_ALGORITHM));
      builder.addKeyTransRecipient(x509Cert.getCert(), oaepAlgId);
    } else if (privateKey instanceof ECPrivateKey) {
      // We use ECDHE with AES Key Wrap (standard for EC-based CMS)
      KeySpec keySpec = KeySpec.ofPublicKey(x509Cert.subjectPublicKeyInfo());
      KeyPair keyPair = KeyUtil.generateKeyPair(keySpec, random);
      builder.addKeyAgreeRecipient(x509Cert.getCert(), CmsAlgorithm.ECDH_SHA256KDF,
          CmsAlgorithm.AES256_WRAP, keyPair);
    } else {
      throw new IllegalArgumentException(
          "unsupported key class " + privateKey.getClass().getName());
    }

    byte[] data = new byte[100];
    random.nextBytes(data);
    CmsEnvelopedData envelopedData = builder.build(CmsAlgorithm.AES256_GCM, data);

    CmsEnvelopedData ed = new CmsEnvelopedData(envelopedData.toASN1Structure());
    CmsRecipient recipient = ed.getRecipient(x509Cert.getCert());
    Assert.assertNotNull("recipient", recipient);
    Assert.assertArrayEquals(data, recipient.decrypt(privateKey));
  }

}
