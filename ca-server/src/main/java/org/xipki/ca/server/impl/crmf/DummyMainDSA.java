package org.xipki.ca.server.impl.crmf;

import java.io.File;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.crmf.EncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.KeyWrapper;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.xipki.common.util.IoUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;

public class DummyMainDSA {

  public static void main(String[] args) {
    try {
      ff();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
  
  private static void ff() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    ASN1ObjectIdentifier curveOid = SECObjectIdentifiers.secp256r1;
    KeyPair requestor = 
        //KeyUtil.generateRSAKeypair(2048, BigInteger.valueOf(0x10001), new SecureRandom());
        KeyUtil.generateECKeypair(curveOid, new SecureRandom());
    
    PublicKey reqPub = requestor.getPublic();

    KeyWrapper wrapper = null;
    if (reqPub instanceof RSAPublicKey) {
      SubjectPublicKeyInfo spki = KeyUtil.createSubjectPublicKeyInfo(requestor.getPublic());
      wrapper = new RSAOAEPAsymmetricKeyWrapper(spki);
    } else if (reqPub instanceof ECPublicKey) {
      wrapper = new ECIESAsymmetricKeyWrapper(reqPub);
    } else {
      throw new Exception("Requestors's public key cannot be used for encryption");
    }

    JceCRMFEncryptorBuilder encryptorBuilder =
        new JceCRMFEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC);
    OutputEncryptor encryptor = encryptorBuilder.build();
    EncryptedValueBuilder builder = new EncryptedValueBuilder(wrapper, encryptor);

    KeyPair kp = KeyUtil.generateDSAKeypair(2048, 256, new SecureRandom());
    SubjectPublicKeyInfo grantedPublicKeyInfo = 
        KeyUtil.createSubjectPublicKeyInfo((DSAPublicKey) kp.getPublic());

    // DSA private keys are represented as BER-encoded ASN.1 type INTEGER.
    DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();
    PrivateKeyInfo transportPrivKey = new PrivateKeyInfo(grantedPublicKeyInfo.getAlgorithm(),
        new ASN1Integer(priv.getX()));

    EncryptedValue encKey = builder.build(transportPrivKey);
    IoUtil.save(new File("encrypted-privkey.tmp"), encKey.getEncoded());
    
    byte[] decKey = decrypt(encKey, requestor.getPrivate());
    IoUtil.save(new File("decrypted-privkey.tmp"), decKey);
  }

  protected static byte[] decrypt(EncryptedValue ev, PrivateKey decKey) throws XiSecurityException {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    ASN1ObjectIdentifier keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;

    try {
      if (decKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
        Cipher keyCipher;
        if (keyOid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPparams params = RSAESOAEPparams.getInstance(keyAlg.getParameters());
            ASN1ObjectIdentifier oid = params.getHashAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
          keyCipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
        } else {
          throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, decKey);

        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else if (decKey instanceof ECPrivateKey) {
        ASN1Sequence params = ASN1Sequence.getInstance(keyAlg.getParameters());
        final int n = params.size();
        for (int i = 0; i < n; i++) {
          if (!keyOid.equals(ObjectIdentifiers.id_ecies_specifiedParameters)) {
            throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
          }

          ASN1TaggedObject to = (ASN1TaggedObject) params.getObjectAt(i);
          int tag = to.getTagNo();
          if (tag == 0) { // KDF
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_iso18033_kdf2.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported KeyDerivationFunction.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException(
                  "unsupported KeyDerivationFunction " + algId.getAlgorithm().getId());
            }
          } else if (tag == 1) { // SymmetricEncryption
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (!ObjectIdentifiers.id_aes128_cbc_in_ecies.equals(algId.getAlgorithm())) {
              throw new XiSecurityException("unsupported SymmetricEncryption "
                  + algId.getAlgorithm().getId());
            }
          } else if (tag == 2) { // MessageAuthenticationCode
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_hmac_full_ecies.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported MessageAuthenticationCode.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException("unsupported MessageAuthenticationCode "
                  + algId.getAlgorithm().getId());
            }
          }
        }

        Cipher keyCipher = Cipher.getInstance("ECIESWITHAES-CBC", "BC");
        IESParameterSpec spec = new IESParameterSpec(null, null, 128, 128, new byte[16]);
        keyCipher.init(Cipher.DECRYPT_MODE, decKey, spec);
        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else {
        throw new XiSecurityException("unsupported decryption key type "
            + decKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      if (!(symmAlg.getAlgorithm().equals(CMSAlgorithm.AES128_CBC)
          || symmAlg.getAlgorithm().equals(CMSAlgorithm.AES192_CBC)
          || symmAlg.getAlgorithm().equals(CMSAlgorithm.AES256_CBC))) {
        // currently we only support AES128-CBC
        throw new XiSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
      }

      Cipher dataCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      /*
       * As defined in §4.1 in RFC 3565:
       * The AlgorithmIdentifier parameters field MUST be present, and the
       * parameters field MUST contain a AES-IV:
       *
       *     AES-IV ::= OCTET STRING (SIZE(16))
       */
      byte[] octets = ev.getEncValue().getOctets();
      // some implementations, like BouncyCastle encapsulates the encrypted in PKCS#8
      // EncryptedPrivateKeyInfo.
      try {
        EncryptedPrivateKeyInfo epki = EncryptedPrivateKeyInfo.getInstance(octets);
        octets = epki.getEncryptedData();
      } catch (IllegalArgumentException ex) {
        // do nothing, it is not an EncryptedPrivateKeyInfo.
      }
      
      byte[] iv = DEROctetString.getInstance(symmAlg.getParameters()).getOctets();
      AlgorithmParameterSpec algParams = new IvParameterSpec(iv);
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);
      System.out.println(octets.length);
      return dataCipher.doFinal(octets);
    } catch (Exception ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  }


}
