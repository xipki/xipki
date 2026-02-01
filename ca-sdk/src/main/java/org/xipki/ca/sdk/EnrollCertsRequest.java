// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;
import org.xipki.util.extra.type.EmbedCertsMode;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class EnrollCertsRequest extends SdkRequest {

  private String transactionId;

  /**
   * For case to enroll more than 1 certificates in one request, default to
   * false.
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
  private EmbedCertsMode caCertMode;

  private Entry[] entries;

  public String transactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Boolean groupEnroll() {
    return groupEnroll;
  }

  public void setGroupEnroll(Boolean groupEnroll) {
    this.groupEnroll = groupEnroll;
  }

  public Boolean explicitConfirm() {
    return explicitConfirm;
  }

  public void setExplicitConfirm(Boolean explicitConfirm) {
    this.explicitConfirm = explicitConfirm;
  }

  public Integer confirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public void setConfirmWaitTimeMs(Integer confirmWaitTimeMs) {
    this.confirmWaitTimeMs = confirmWaitTimeMs;
  }

  public EmbedCertsMode caCertMode() {
    return caCertMode;
  }

  public void setCaCertMode(EmbedCertsMode caCertMode) {
    this.caCertMode = caCertMode;
  }

  public Entry[] entries() {
    return entries;
  }

  public void setEntries(Entry[] entries) {
    this.entries = entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(6).writeTextString(transactionId)
        .writeBooleanObj(groupEnroll).writeBooleanObj(explicitConfirm)
        .writeIntObj(confirmWaitTimeMs).writeEnumObj(caCertMode)
        .writeObjects(entries);
  }

  public static EnrollCertsRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("EnrollCertsRequest", decoder, 6);
      EnrollCertsRequest ret = new EnrollCertsRequest();
      ret.setTransactionId(decoder.readTextString());
      ret.setGroupEnroll(decoder.readBooleanObj());
      ret.setExplicitConfirm(decoder.readBooleanObj());
      ret.setConfirmWaitTimeMs(decoder.readIntObj());
      String str = decoder.readTextString();
      if (str != null) {
        ret.setCaCertMode(EmbedCertsMode.valueOf(str));
      }
      ret.setEntries(Entry.decodeArray(decoder));
      return ret;
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, EnrollCertsRequest.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    private BigInteger certReqId;

    private String certprofile;

    /**
     * Specifies the PKCS#10 Request. Note that the CA does NOT verify the
     * signature of this request. You may also put any dummy value in the
     * signature field. The verification of CSR must be processed by the CA
     * client calling the enrolment service.
     * <p>
     * If p10req is set, the {@link #subject}, {@link #subjectPublicKey} and
     * {@link #extensions} will be ignored.
     */
    private byte[] p10req;

    /**
     * Specifies the Subject. If not for re-enroll, subject must be set if
     * p10req is not present, set it to empty string if empty subject is
     * expected. Must be set if p10req is not present.
     */
    private X500NameType subject;

    /**
     * Specifies the DER-encoded SubjectPublicKeyInfo.
     * If both this and the p10req is not set, CA will generate the keypair.
     */
    private byte[] subjectPublicKey;

    /**
     * Specifies the additional extensions. Will be considered only if p10req
     * is not present.
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

    public BigInteger certReqId() {
      return certReqId;
    }

    public void setCertReqId(BigInteger certReqId) {
      this.certReqId = certReqId;
    }

    public String certprofile() {
      return certprofile;
    }

    public void setCertprofile(String certprofile) {
      this.certprofile = certprofile;
    }

    public byte[] subjectPublicKey() {
      return subjectPublicKey;
    }

    public void setSubjectPublicKey(byte[] subjectPublicKey) {
      this.subjectPublicKey = subjectPublicKey;
    }

    public void subjectPublicKey(SubjectPublicKeyInfo subjectPublicKey)
        throws IOException {
      this.subjectPublicKey = subjectPublicKey == null ? null
          : subjectPublicKey.getEncoded();
    }

    public X500NameType subject() {
      return subject;
    }

    public void setSubject(X500NameType subject) {
      this.subject = subject;
    }

    public byte[] extensions() {
      return extensions;
    }

    public void setExtensions(byte[] extensions) {
      this.extensions = extensions;
    }

    public void extensions(Extensions extensions) throws IOException {
      this.extensions = extensions == null ? null : extensions.getEncoded();
    }

    public byte[] p10req() {
      return p10req;
    }

    public void setP10req(byte[] p10req) {
      this.p10req = p10req;
    }

    public Instant notBefore() {
      return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
      this.notBefore = notBefore;
    }

    public Instant notAfter() {
      return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
      this.notAfter = notAfter;
    }

    public OldCertInfo oldCertInfo() {
      return oldCertInfo;
    }

    public void setOldCertInfo(OldCertInfo oldCertInfo) {
      this.oldCertInfo = oldCertInfo;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws CodecException {
      encoder.writeArrayStart(9);
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

    public static Entry decode(CborDecoder decoder) throws CodecException {
      try {
        if (decoder.readNullOrArrayLength(9)) {
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
      } catch (RuntimeException ex) {
        throw new CodecException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder)
        throws CodecException {
      Integer arrayLen = decoder.readNullOrArrayLength();
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
