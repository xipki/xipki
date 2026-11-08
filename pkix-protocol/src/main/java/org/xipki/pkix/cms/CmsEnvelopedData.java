// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.asn1.cms.*;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.util.exception.PkixException;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * CMS EnvelopedData (RFC 5652, section 6).
 *
 * @author Lijun Liao (xipki)
 */
public class CmsEnvelopedData {

  public static class Builder {

    private interface RecipientSpec {
      RecipientInfo build(byte[] cek) throws PkixException;
    }

    private static final AlgorithmIdentifier RSA_PKCS15 =
        AlgorithmIdentifier.ofNullParams(PkcsOIDs.rsaEncryption);

    private final List<RecipientSpec> recipients = new ArrayList<>();

    /**
     * Adds a key transport recipient with RSA PKCS#1 v1.5.
     * @param cert the certificate of the recipient.
     * @return this builder.
     */
    public Builder addKeyTransRecipient(Certificate cert) {
      return addKeyTransRecipient(cert, RSA_PKCS15);
    }

    /**
     * Adds a key transport recipient.
     * @param cert the certificate of the recipient.
     * @param keyEncryptionAlgorithm the key encryption algorithm, rsaEncryption (PKCS#1 v1.5) or
     *        id-RSAES-OAEP.
     * @return this builder.
     */
    public Builder addKeyTransRecipient(
        Certificate cert, AlgorithmIdentifier keyEncryptionAlgorithm) {
      Args.notNull(cert, "cert");
      Args.notNull(keyEncryptionAlgorithm, "keyEncryptionAlgorithm");
      recipients.add(cek -> {
        byte[] encryptedKey = CmsCrypto.keyTransEncrypt(keyEncryptionAlgorithm,
            CmsCrypto.publicKey(cert.getSubjectPublicKeyInfo()), cek);
        RecipientIdentifier rid = RecipientIdentifier.ofIssuerAndSerialNumber(
            new IssuerAndSerialNumber(cert));
        return RecipientInfo.ofKtri(
            new KeyTransRecipientInfo(rid, keyEncryptionAlgorithm, encryptedKey));
      });
      return this;
    }

    /**
     * Adds a key agreement recipient with ECDH and X9.63 KDF (RFC 5753).
     * @param cert the certificate of the recipient.
     * @param keyAgreementAlgorithm the key agreement algorithm, e.g.
     *        {@link CmsAlgorithm#ECDH_SHA256KDF}.
     * @param keyWrapAlgorithm the key wrap algorithm, e.g. {@link CmsAlgorithm#AES256_WRAP}.
     * @param originatorKeyPair the (ephemeral) key pair of the originator.
     * @return this builder.
     */
    public Builder addKeyAgreeRecipient(
        Certificate cert, Asn1Oid keyAgreementAlgorithm, Asn1Oid keyWrapAlgorithm,
        KeyPair originatorKeyPair) {
      Args.notNull(cert, "cert");
      Args.notNull(keyAgreementAlgorithm, "keyAgreementAlgorithm");
      Args.notNull(keyWrapAlgorithm, "keyWrapAlgorithm");
      Args.notNull(originatorKeyPair, "originatorKeyPair");
      if (!CmsCrypto.isEcdhKdf(keyAgreementAlgorithm)) {
        throw new IllegalArgumentException(
            "unsupported key agreement algorithm " + keyAgreementAlgorithm.getId());
      }

      recipients.add(cek -> {
        SubjectPublicKeyInfo originatorKeyInfo;
        try {
          originatorKeyInfo = SubjectPublicKeyInfo.fromPublicKey(originatorKeyPair.getPublic());
        } catch (CodecException e) {
          throw new PkixException("invalid originator public key", e);
        }

        AlgorithmIdentifier wrapAlg = new AlgorithmIdentifier(keyWrapAlgorithm);
        byte[] encryptedKey = CmsCrypto.keyAgreeWrap(Cipher.WRAP_MODE, keyAgreementAlgorithm,
            wrapAlg, originatorKeyPair.getPrivate(),
            CmsCrypto.publicKey(cert.getSubjectPublicKeyInfo()), null, cek);

        OriginatorIdentifierOrKey originator = OriginatorIdentifierOrKey.ofOriginatorKey(
            new OriginatorPublicKey(originatorKeyInfo.getAlgorithm(),
                originatorKeyInfo.subjectPublicKey()));
        RecipientEncryptedKey rek = new RecipientEncryptedKey(
            KeyAgreeRecipientIdentifier.ofIssuerAndSerialNumber(new IssuerAndSerialNumber(cert)),
            encryptedKey);
        return RecipientInfo.ofKari(new KeyAgreeRecipientInfo(originator, null,
            AlgorithmIdentifier.build(keyAgreementAlgorithm, wrapAlg),
            new RecipientEncryptedKey.Seq0(rek)));
      });
      return this;
    }

    /**
     * Adds a password recipient (RFC 3211) with PBKDF2.
     * @param password the password.
     * @param keyEncryptionAlgorithm the key encryption algorithm, one of
     *        {@link CmsAlgorithm#AES128_CBC}, {@link CmsAlgorithm#AES192_CBC},
     *        {@link CmsAlgorithm#AES256_CBC} and {@link CmsAlgorithm#DES_EDE3_CBC}.
     * @param prf the PRF of PBKDF2, e.g. AlgorithmIdentifier of id-hmacWithSHA256.
     * @param salt the salt of PBKDF2.
     * @param iterationCount the iteration count of PBKDF2.
     * @return this builder.
     */
    public Builder addPasswordRecipient(
        char[] password, Asn1Oid keyEncryptionAlgorithm, AlgorithmIdentifier prf,
        byte[] salt, int iterationCount) {
      Args.notNull(password, "password");
      Args.notNull(prf, "prf");
      Args.notNull(salt, "salt");
      Args.positive(iterationCount, "iterationCount");
      int keySize = CmsCrypto.passwordKekKeySize(Args.notNull(keyEncryptionAlgorithm,
          "keyEncryptionAlgorithm"));
      if (keySize == 0) {
        throw new IllegalArgumentException(
            "unsupported key encryption algorithm " + keyEncryptionAlgorithm.getId());
      }

      recipients.add(cek -> {
        PBKDF2Params pbkdf2Params = new PBKDF2Params(salt, iterationCount, prf);
        byte[] kek = CmsCrypto.pbkdf2(password, pbkdf2Params, keySize);

        byte[] iv = new byte[CmsCrypto.passwordKekBlockSize(keyEncryptionAlgorithm)];
        CmsCrypto.random().nextBytes(iv);
        byte[] encryptedKey = CmsCrypto.rfc3211Wrap(
            Cipher.WRAP_MODE, keyEncryptionAlgorithm, kek, iv, cek);

        AlgorithmIdentifier kekAlg = AlgorithmIdentifier.build(PkcsOIDs.id_alg_PWRI_KEK,
            new AlgorithmIdentifier(keyEncryptionAlgorithm, new Asn1OctetString(iv)));
        return RecipientInfo.ofPwri(new PasswordRecipientInfo(
            AlgorithmIdentifier.build(PkcsOIDs.id_PBKDF2, pbkdf2Params), kekAlg, encryptedKey));
      });
      return this;
    }

    /**
     * Encrypts the content (of type id-data) for all recipients.
     * @param contentEncryptionAlgorithm the content encryption algorithm, e.g.
     *        {@link CmsAlgorithm#AES256_GCM}.
     * @param content the content.
     * @return the EnvelopedData.
     * @throws PkixException if the EnvelopedData cannot be built.
     */
    public CmsEnvelopedData build(Asn1Oid contentEncryptionAlgorithm, byte[] content)
        throws PkixException {
      Args.notNull(contentEncryptionAlgorithm, "contentEncryptionAlgorithm");
      Args.notNull(content, "content");
      if (recipients.isEmpty()) {
        throw new PkixException("no recipient is specified");
      }

      CmsCrypto.EncryptedContent ec = CmsCrypto.encryptContent(contentEncryptionAlgorithm, content);

      List<RecipientInfo> recipientInfos = new ArrayList<>(recipients.size());
      for (RecipientSpec spec : recipients) {
        recipientInfos.add(spec.build(ec.cek));
      }

      EncryptedContentInfo eci = new EncryptedContentInfo(CmsOIDs.data, ec.algorithm,
          ec.encryptedContent);
      return new CmsEnvelopedData(
          new EnvelopedData(null, new RecipientInfos(recipientInfos), eci, null));
    }

  }

  private final EnvelopedData envelopedData;

  private final List<CmsRecipient> recipients;

  public CmsEnvelopedData(byte[] encoded) throws PkixException {
    this(parseContentInfo(encoded));
  }

  public CmsEnvelopedData(ContentInfo contentInfo) throws PkixException {
    this(parseEnvelopedData(contentInfo));
  }

  public CmsEnvelopedData(EnvelopedData envelopedData) throws PkixException {
    this.envelopedData = Args.notNull(envelopedData, "envelopedData");

    List<CmsRecipient> list = new ArrayList<>();
    try {
      for (RecipientInfo ri : envelopedData.getRecipientInfos()) {
        if (ri.hasKtri()) {
          list.add(CmsRecipient.ofKeyTrans(this, ri.getKtri()));
        } else if (ri.hasKari()) {
          KeyAgreeRecipientInfo kari = ri.getKari();
          for (RecipientEncryptedKey karKey : kari.getRecipientEncryptedKeys()) {
            list.add(CmsRecipient.ofKeyAgree(this, kari, karKey));
          }
        } else if (ri.hasPwri()) {
          list.add(CmsRecipient.ofPassword(this, ri.getPwri()));
        } else {
          list.add(CmsRecipient.ofOther(this));
        }
      }
    } catch (RuntimeException e) {
      throw new PkixException("malformed EnvelopedData: " + e.getMessage(), e);
    }
    this.recipients = Collections.unmodifiableList(list);
  }

  private static ContentInfo parseContentInfo(byte[] encoded) throws PkixException {
    try {
      return ContentInfo.fromEncoded(Args.notNull(encoded, "encoded"));
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed ContentInfo: " + e.getMessage(), e);
    }
  }

  private static EnvelopedData parseEnvelopedData(ContentInfo contentInfo) throws PkixException {
    if (!CmsOIDs.envelopedData.equals(Args.notNull(contentInfo, "contentInfo").getContentType())) {
      throw new PkixException("content type is not id-envelopedData, but "
          + contentInfo.getContentType().getId());
    }

    try {
      return EnvelopedData.fromAsn1(contentInfo.getContent().asSequence());
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed EnvelopedData: " + e.getMessage(), e);
    }
  }

  public AlgorithmIdentifier getContentEncryptionAlgorithm() {
    return envelopedData.getEncryptedContentInfo().getContentEncryptionAlgorithm();
  }

  public List<CmsRecipient> getRecipients() {
    return recipients;
  }

  /**
   * Returns the first key transport or key agreement recipient identified by the given
   * certificate.
   * @param cert the certificate of the recipient.
   * @return the matched recipient, or {@code null} if there is no such recipient.
   */
  public CmsRecipient getRecipient(Certificate cert) {
    Args.notNull(cert, "cert");
    for (CmsRecipient recipient : recipients) {
      if (recipient.matches(cert)) {
        return recipient;
      }
    }
    return null;
  }

  byte[] decryptContent(byte[] cek) throws PkixException {
    EncryptedContentInfo eci = envelopedData.getEncryptedContentInfo();
    byte[] encryptedContent = eci.encryptedContent();
    if (encryptedContent == null) {
      throw new PkixException("encryptedContent is absent");
    }
    return CmsCrypto.decryptContent(eci.getContentEncryptionAlgorithm(), cek, encryptedContent);
  }

  public EnvelopedData getEnvelopedData() {
    return envelopedData;
  }

  public ContentInfo toASN1Structure() {
    return ContentInfo.build(CmsOIDs.envelopedData, envelopedData);
  }

  public byte[] getEncoded() {
    return toASN1Structure().getEncoded();
  }

}
