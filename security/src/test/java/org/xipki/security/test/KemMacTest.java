// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.SignAlgo;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.encap.KemEncapsulation;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.HmacContentSigner;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SecretKeyWithAlias;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class KemMacTest {

  @Test
  public void signVerify() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(KeyUtil.newBouncyCastleProvider());
    }

    // only the verifier has the master key
    String alias = "alias";
    SecretKeySpec masterKey0 = new SecretKeySpec(new byte[32], "AES");
    SecretKeyWithAlias masterKey = new SecretKeyWithAlias(alias, masterKey0);

    // Sender: generates keypair
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-KEM-512");
    KeyPair myKeyPair = kpGen.generateKeyPair();

    SubjectPublicKeyInfo myPkInfo = SubjectPublicKeyInfo.getInstance(
        myKeyPair.getPublic().getEncoded());

    // Receiver: generates encapsulated MAC key
    KemEncapKey kemEncapKey;
    {
      SecureRandom rnd = new SecureRandom();
      kemEncapKey = KEMUtil.generateKemEncapKey(myPkInfo, masterKey, rnd);
    }

    // Sender: decrypts the mac key using private key
    byte[] macKeyBytes;
    {
      byte alg = kemEncapKey.getEncapulation().getAlg();
      if (alg != KemEncapsulation.ALG_KMAC_MLKEM_HMAC) {
        throw new XiSecurityException("unknown wrap mechanism " + alg);
      }

      macKeyBytes = KEMUtil.mlkemDecryptSecret(myKeyPair.getPrivate(),
          kemEncapKey.getEncapulation());
    }

    // Sender: compute the HMAC value
    byte[] data = new byte[100];
    byte[] sig;
    {
      SecretKey macKey = new SecretKeySpec(macKeyBytes, "AES");
      Mac mac = Mac.getInstance("HMAC-SHA256");
      mac.init(macKey);
      mac.update(data);
      byte[] rawSignature = mac.doFinal();

      try {
        DERUTF8String utf8Id = new DERUTF8String(kemEncapKey.getId());
        sig = new DERSequence(new ASN1Encodable[]{utf8Id,
                new DEROctetString(rawSignature)}).getEncoded();
      } catch (IOException e) {
        throw new IllegalStateException("error encoding the DER signature");
      }
    }

    // Verifier: verify the mac value
    {
      ASN1Sequence seq = ASN1Sequence.getInstance(sig);
      // id: will be used to identify the mackey. not used currently.
      // ASN1UTF8String id = (ASN1UTF8String) seq.getObjectAt(0);
      byte[] rawSignature = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();

      byte[] rawPkData = myPkInfo.getPublicKeyData().getOctets();
      byte[] secret = KEMUtil.kmacDerive(masterKey.getSecretKey(), 32,
          "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);

      SecretKey macKey = new SecretKeySpec(secret, "AES");

      HmacContentSigner verifier = new HmacContentSigner(
          SignAlgo.HMAC_SHA256, macKey);

      verifier.getOutputStream().write(data);
      byte[] macValue = verifier.getSignature();
      boolean valid = Arrays.equals(rawSignature, macValue);
      Assert.assertTrue("signature invalid", valid);
    }

  }

}
