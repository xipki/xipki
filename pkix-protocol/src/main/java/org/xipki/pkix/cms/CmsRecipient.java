// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.cms.KeyAgreeRecipientIdentifier;
import org.xipki.pkix.asn1.cms.KeyAgreeRecipientInfo;
import org.xipki.pkix.asn1.cms.KeyTransRecipientInfo;
import org.xipki.pkix.asn1.cms.OriginatorPublicKey;
import org.xipki.pkix.asn1.cms.PasswordRecipientInfo;
import org.xipki.pkix.asn1.cms.RecipientEncryptedKey;
import org.xipki.pkix.asn1.cms.RecipientIdentifier;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.util.exception.PkixException;

import javax.crypto.Cipher;
import java.security.PrivateKey;

/**
 * A recipient (RecipientInfo) of the CMS EnvelopedData. For the key agreement, each recipient
 * encrypted key is a recipient.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsRecipient {

  public enum Type {
    KEY_TRANS,
    KEY_AGREE,
    PASSWORD,
    /** KEK, KEM and other recipients, which cannot be decrypted by this class. */
    OTHER
  }

  private final Type type;

  private final CmsEnvelopedData envelopedData;

  private final KeyTransRecipientInfo ktri;

  private final KeyAgreeRecipientInfo kari;

  private final RecipientEncryptedKey karKey;

  private final PasswordRecipientInfo pwri;

  private final IssuerAndSerialNumber issuerAndSerialNumber;

  private final byte[] subjectKeyIdentifier;

  private CmsRecipient(
      Type type, CmsEnvelopedData envelopedData, KeyTransRecipientInfo ktri,
      KeyAgreeRecipientInfo kari, RecipientEncryptedKey karKey, PasswordRecipientInfo pwri,
      IssuerAndSerialNumber issuerAndSerialNumber, byte[] subjectKeyIdentifier) {
    this.type = type;
    this.envelopedData = envelopedData;
    this.ktri = ktri;
    this.kari = kari;
    this.karKey = karKey;
    this.pwri = pwri;
    this.issuerAndSerialNumber = issuerAndSerialNumber;
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  static CmsRecipient ofKeyTrans(CmsEnvelopedData envelopedData, KeyTransRecipientInfo ktri) {
    RecipientIdentifier rid = ktri.getRid();
    return new CmsRecipient(Type.KEY_TRANS, envelopedData, ktri, null, null, null,
        rid.getIssuerAndSerialNumber(), rid.subjectKeyIdentifier());
  }

  static CmsRecipient ofKeyAgree(CmsEnvelopedData envelopedData, KeyAgreeRecipientInfo kari,
                                 RecipientEncryptedKey karKey) {
    KeyAgreeRecipientIdentifier rid = karKey.getIdentifier();
    byte[] ski = rid.getRKeyID() == null ? null : rid.getRKeyID().subjectKeyIdentifier();
    return new CmsRecipient(Type.KEY_AGREE, envelopedData, null, kari, karKey, null,
        rid.getIssuerAndSerialNumber(), ski);
  }

  static CmsRecipient ofPassword(CmsEnvelopedData envelopedData, PasswordRecipientInfo pwri) {
    return new CmsRecipient(Type.PASSWORD, envelopedData, null, null, null, pwri, null, null);
  }

  static CmsRecipient ofOther(CmsEnvelopedData envelopedData) {
    return new CmsRecipient(Type.OTHER, envelopedData, null, null, null, null, null, null);
  }

  public Type getType() {
    return type;
  }

  /**
   * Returns whether the given certificate is identified by this key transport or key agreement
   * recipient.
   * @param cert the certificate.
   * @return true if the certificate is identified by this recipient, false otherwise.
   */
  boolean matches(Certificate cert) {
    return CmsSigner.matches(issuerAndSerialNumber, subjectKeyIdentifier, cert);
  }

  /**
   * Decrypts the content as key transport or key agreement recipient.
   * @param key the private key of the recipient.
   * @return the decrypted content.
   * @throws PkixException if the content cannot be decrypted.
   */
  public byte[] decrypt(PrivateKey key) throws PkixException {
    Args.notNull(key, "key");
    byte[] cek;
    if (type == Type.KEY_TRANS) {
      cek = CmsCrypto.keyTransDecrypt(ktri.getKeyEncryptionAlgorithm(), key,
          ktri.encryptedKey());
    } else if (type == Type.KEY_AGREE) {
      cek = unwrapKeyAgree(key);
    } else {
      throw new PkixException("decryption with private key is not supported for " + type);
    }

    return envelopedData.decryptContent(cek);
  }

  /**
   * Decrypts the content as password recipient (RFC 3211).
   * @param password the password.
   * @return the decrypted content.
   * @throws PkixException if the content cannot be decrypted.
   */
  public byte[] decrypt(char[] password) throws PkixException {
    Args.notNull(password, "password");
    if (type != Type.PASSWORD) {
      throw new PkixException("decryption with password is not supported for " + type);
    }

    try {
      AlgorithmIdentifier kdAlg = pwri.getKeyDerivationAlgorithm();
      if (kdAlg == null || !PkcsOIDs.id_PBKDF2.equals(kdAlg.getAlgorithm())) {
        throw new PkixException("unsupported key derivation algorithm");
      }

      AlgorithmIdentifier kekAlg = pwri.getKeyEncryptionAlgorithm();
      if (!PkcsOIDs.id_alg_PWRI_KEK.equals(kekAlg.getAlgorithm())) {
        throw new PkixException("unsupported key encryption algorithm "
            + kekAlg.getAlgorithm().getId());
      }

      AlgorithmIdentifier kekParams = AlgorithmIdentifier.fromAsn1(
          kekAlg.getParameters().asSequence());
      int keySize = CmsCrypto.passwordKekKeySize(kekParams.getAlgorithm());
      if (keySize == 0) {
        throw new PkixException("unsupported key encryption algorithm "
            + kekParams.getAlgorithm().getId());
      }

      byte[] kek = CmsCrypto.pbkdf2(password,
          PBKDF2Params.fromAsn1(kdAlg.getParameters().asSequence()), keySize);
      byte[] iv = kekParams.getParameters().asOctetString().getOctets();
      byte[] cek = CmsCrypto.rfc3211Wrap(Cipher.UNWRAP_MODE, kekParams.getAlgorithm(), kek, iv,
          pwri.encryptedKey());
      return envelopedData.decryptContent(cek);
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed PasswordRecipientInfo: " + e.getMessage(), e);
    }
  }

  private byte[] unwrapKeyAgree(PrivateKey key) throws PkixException {
    try {
      OriginatorPublicKey originatorKey = kari.getOriginator().getOriginatorKey();
      if (originatorKey == null) {
        throw new PkixException("only originatorKey is supported as originator");
      }

      AlgorithmIdentifier keyEncAlg = kari.getKeyEncryptionAlgorithm();
      AlgorithmIdentifier wrapAlg = AlgorithmIdentifier.fromAsn1(
          keyEncAlg.getParameters().asSequence());

      // the originator key may omit the domain parameters, use the ones of the recipient key.
      AlgorithmIdentifier keyAlg = PrivateKeyInfo.algorithmFromPrivateKey(key);
      SubjectPublicKeyInfo senderKeyInfo =
          new SubjectPublicKeyInfo(keyAlg, originatorKey.publicKeyData());

      return CmsCrypto.keyAgreeWrap(Cipher.UNWRAP_MODE, keyEncAlg.getAlgorithm(), wrapAlg, key,
          CmsCrypto.publicKey(senderKeyInfo), kari.ukm(), karKey.encryptedKey());
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed KeyAgreeRecipientInfo: " + e.getMessage(), e);
    }
  }

}
