// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
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

public class EnrollCertsRequest extends SdkRequest {

  private String transactionId;

  /**
   * For case to enroll more than 1 certificates in one request, default to false.
   * <ul>
   *   <li>true: either all certificates have been enrolled or failed.</li>
   *   <li>false: each certificate may have been enrolled or failed</li>
   * </ul>
   */
  private Boolean groupEnroll;

  /**
   * Whether an explicit confirm is required. Default to false.
   */
  private Boolean explicitConfirm;

  private Integer confirmWaitTimeMs;

  /**
   * Specifies how to embed the CA certificate in the response:
   */
  private CertsMode caCertMode;

  private Entry[] entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Boolean getGroupEnroll() {
    return groupEnroll;
  }

  public void setGroupEnroll(Boolean groupEnroll) {
    this.groupEnroll = groupEnroll;
  }

  public Boolean getExplicitConfirm() {
    return explicitConfirm;
  }

  public void setExplicitConfirm(Boolean explicitConfirm) {
    this.explicitConfirm = explicitConfirm;
  }

  public Integer getConfirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public void setConfirmWaitTimeMs(Integer confirmWaitTimeMs) {
    this.confirmWaitTimeMs = confirmWaitTimeMs;
  }

  public CertsMode getCaCertMode() {
    return caCertMode;
  }

  public void setCaCertMode(CertsMode caCertMode) {
    this.caCertMode = caCertMode;
  }

  public Entry[] getEntries() {
    return entries;
  }

  public void setEntries(Entry[] entries) {
    this.entries = entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
    encoder.writeArrayStart(6);
    encoder.writeTextString(transactionId);
    encoder.writeBooleanObj(groupEnroll);
    encoder.writeBooleanObj(explicitConfirm);
    encoder.writeIntObj(confirmWaitTimeMs);
    encoder.writeEnumObj(caCertMode);
    encoder.writeObjects(entries);
  }

  public static EnrollCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("EnrollCertsRequest", decoder, 6);
      EnrollCertsRequest ret = new EnrollCertsRequest();
      ret.setTransactionId(decoder.readTextString());
      ret.setGroupEnroll(decoder.readBooleanObj());
      ret.setExplicitConfirm(decoder.readBooleanObj());
      ret.setConfirmWaitTimeMs(decoder.readIntObj());
      String str = decoder.readTextString();
      if (str != null) {
        ret.setCaCertMode(CertsMode.valueOf(str));
      }
      ret.setEntries(Entry.decodeArray(decoder));
      return ret;
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, EnrollCertsRequest.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    private BigInteger certReqId;

    private String certprofile;

    /**
     * Specifies the PKCS#10 Request. Note that the CA does NOT verify the signature of
     * this request. You may also put any dummy value in the signature field.
     * The verification of CSR must be processed by the CA client calling
     * the enrolment service.
     * <p>
     * If p10req is set, the {@link #subject}, {@link #subjectPublicKey} and
     * {@link #extensions} will be ignored.
     */
    private byte[] p10req;

    /**
     * Specifies the Subject. If not for re-enroll, subject must be set if p10req is not present,
     * set it to empty string if empty subject is expected. Must be set if p10req is not present.
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
    private Instant notBefore;

    /**
     * Epoch time in seconds of not-after.
     */
    private Instant notAfter;

    private OldCertInfo oldCertInfo;

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

    public Instant getNotBefore() {
      return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
      this.notBefore = notBefore;
    }

    public void notBefore(Instant notBefore) {
      this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
      this.notAfter = notAfter;
    }

    public void notAfter(Instant notAfter) {
      this.notAfter = notAfter;
    }

    public OldCertInfo getOldCertInfo() {
      return oldCertInfo;
    }

    public void setOldCertInfo(OldCertInfo oldCertInfo) {
      this.oldCertInfo = oldCertInfo;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(10);
      encoder.writeBigInt(certReqId);
      encoder.writeTextString(certprofile);
      encoder.writeByteString(p10req);
      encoder.writeObject(subject);
      encoder.writeByteString(subjectPublicKey);
      encoder.writeByteString(extensions);
      encoder.writeInstant(notBefore);
      encoder.writeInstant(notAfter);
      encoder.writeObject(oldCertInfo);
    }

    public static Entry decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(10)) {
          return null;
        }

        Entry ret = new Entry();
        ret.setCertReqId(decoder.readBigInt());
        ret.setCertprofile(decoder.readTextString());
        ret.setP10req(decoder.readByteString());
        ret.setSubject(X500NameType.decode(decoder));
        ret.setSubjectPublicKey(decoder.readByteString());
        ret.setExtensions(decoder.readByteString());
        ret.setNotBefore(decoder.readInstant());
        ret.setNotAfter(decoder.readInstant());
        ret.setOldCertInfo(OldCertInfo.decode(decoder));
        return ret;
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder) throws DecodeException {
      Integer arrayLen = decoder.readNullOrArrayLength(Entry[].class);
      if (arrayLen == null) {
        return null;
      }

      Entry[] entries = new Entry[arrayLen];
      for (int i = 0; i < arrayLen; i++) {
        entries[i] = Entry.decode(decoder);
      }

      return entries;
    }

  }
}
