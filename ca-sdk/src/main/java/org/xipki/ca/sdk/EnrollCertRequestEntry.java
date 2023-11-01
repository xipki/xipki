// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncodable;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EnrollCertRequestEntry implements CborEncodable {

  private BigInteger certReqId;

  private String certprofile;

  /**
   * Specifies the PKCS#10 Request. Note that the CA ddoes NOT verify the signature of
   * this request. You may also put any dummy value in the signature field.
   * The verification of CSR must be processed by the CA client calling
   * the enrolment service.
   * <p>
   * If p10req is set, the {@link #subject}, {@link #subjectPublicKey} and
   * {@link #extensions} will be ignored.
   */
  private byte[] p10req;

  /**
   * Specifies the Subject. Must be set if p10req is not present, set it to empty string
   * if empty subject is expected. Must be set if p10req is not present.
   */
  private X500NameType subject;

  /**
   * Specifies the DER-encoded SubjectPublicKeyInfo.
   * If both this and the p10req is not set, CA will generate the keypair.
   */
  private byte[] subjectPublicKey;

  /**
   * Specifies the additional extensions. Will be considered only if p10req is not present.
   */
  private byte[] extensions;

  /**
   * Epoch time in seconds of not-before.
   */
  private Long notBefore;

  /**
   * Epoch time in seconds of not-after.
   */
  private Long notAfter;

  private OldCertInfoByIssuerAndSerial oldCertIsn;

  private OldCertInfoBySubject oldCertSubject;

  public BigInteger getCertReqId() {
    return certReqId;
  }

  public void setCertReqId(BigInteger certReqId) {
    this.certReqId = certReqId;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public byte[] getSubjectPublicKey() {
    return subjectPublicKey;
  }

  public void setSubjectPublicKey(byte[] subjectPublicKey) {
    this.subjectPublicKey = subjectPublicKey;
  }

  public void subjectPublicKey(SubjectPublicKeyInfo subjectPublicKey) throws IOException {
    this.subjectPublicKey = subjectPublicKey == null ? null : subjectPublicKey.getEncoded();
  }

  public X500NameType getSubject() {
    return subject;
  }

  public void setSubject(X500NameType subject) {
    this.subject = subject;
  }

  public byte[] getExtensions() {
    return extensions;
  }

  public void setExtensions(byte[] extensions) {
    this.extensions = extensions;
  }

  public void extensions(Extensions extensions) throws IOException {
    this.extensions = extensions == null ? null : extensions.getEncoded();
  }

  public byte[] getP10req() {
    return p10req;
  }

  public void setP10req(byte[] p10req) {
    this.p10req = p10req;
  }

  public Long getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Long notBefore) {
    this.notBefore = notBefore;
  }

  public void notBefore(Instant notBefore) {
    this.notBefore = notBefore == null ? null : notBefore.getEpochSecond();
  }

  public Long getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Long notAfter) {
    this.notAfter = notAfter;
  }

  public void notAfter(Instant notAfter) {
    this.notAfter = notAfter == null ? null : notAfter.getEpochSecond();
  }

  public OldCertInfoByIssuerAndSerial getOldCertIsn() {
    return oldCertIsn;
  }

  public void setOldCertIsn(OldCertInfoByIssuerAndSerial oldCertIsn) {
    this.oldCertIsn = oldCertIsn;
  }

  public OldCertInfoBySubject getOldCertSubject() {
    return oldCertSubject;
  }

  public void setOldCertSubject(OldCertInfoBySubject oldCertSubject) {
    this.oldCertSubject = oldCertSubject;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(10);
      encoder.writeBigInt(certReqId);
      encoder.writeTextString(certprofile);
      encoder.writeByteString(p10req);
      encoder.writeObject(subject);
      encoder.writeByteString(subjectPublicKey);
      encoder.writeByteString(extensions);
      encoder.writeIntObj(notBefore);
      encoder.writeIntObj(notAfter);
      encoder.writeObject(oldCertIsn);
      encoder.writeObject(oldCertSubject);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static EnrollCertRequestEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(10)) {
        return null;
      }

      EnrollCertRequestEntry ret = new EnrollCertRequestEntry();
      ret.setCertReqId(decoder.readBigInt());
      ret.setCertprofile(decoder.readTextString());
      ret.setP10req(decoder.readByteString());
      ret.setSubject(X500NameType.decode(decoder));
      ret.setSubjectPublicKey(decoder.readByteString());
      ret.setExtensions(decoder.readByteString());
      ret.setNotBefore(decoder.readLongObj());
      ret.setNotAfter(decoder.readLongObj());
      ret.setOldCertIsn(OldCertInfoByIssuerAndSerial.decode(decoder));
      ret.setOldCertSubject(OldCertInfoBySubject.decode(decoder));
      return ret;
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + EnrollCertRequestEntry.class.getName(), ex);
    }
  }

  public static EnrollCertRequestEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(EnrollCertRequestEntry[].class);
    if (arrayLen == null) {
      return null;
    }

    EnrollCertRequestEntry[] entries = new EnrollCertRequestEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = EnrollCertRequestEntry.decode(decoder);
    }

    return entries;
  }

}
