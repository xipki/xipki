// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.ctlog;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.Pack;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.Args;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.util.Args.notNull;

/**
 * RFC 6962 implementation of the required classes for the extension SCT in certificate.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLog {

  /**
   * <pre>
   * struct {
   *     SignatureAndHashAlgorithm algorithm;
   *     opaque signature&lt;0..2^16-1&gt;;
   * } DigitallySigned;
   * </pre>
   */
  public static class DigitallySigned {

    private final SignatureAndHashAlgorithm algorithm;

    private final byte[] signature;

    public static DigitallySigned getInstance(byte[] encoded, AtomicInteger offsetObj) {
      int offset = offsetObj.get();

      SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.getInstance(copyOf(encoded, offset, 2));
      offset += 2;

      int signatureLen = readInt2(encoded, offset);
      offset += 2;
      byte[] signature = copyOf(encoded, offset, signatureLen);
      offset += signatureLen;

      offsetObj.set(offset);

      return new DigitallySigned(algorithm, signature);
    }

    public DigitallySigned(SignatureAndHashAlgorithm algorithm, byte[] signature) {
      this.algorithm = notNull(algorithm, "algorithm");
      this.signature = notNull(signature, "signature");
    }

    public SignatureAndHashAlgorithm getAlgorithm() {
      return algorithm;
    }

    public byte[] getSignature() {
      return Arrays.copyOf(signature, signature.length);
    }

    public Object getSignatureObject() {
      if (algorithm.signature == SignatureAlgorithm.ecdsa || algorithm.signature == SignatureAlgorithm.dsa ) {
        ASN1Sequence seq = ASN1Sequence.getInstance(signature);
        return new BigInteger[]{
            ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue()};
      } else {
        return signature;
      }
    }

    public byte[] getEncoded() {
      byte[] ea = algorithm.getEncoded();
      final int n = ea.length + 2 + signature.length;
      byte[] res = new byte[n];
      System.arraycopy(ea, 0, res, 0, ea.length);
      int offset = ea.length;

      // length of signature
      final int sigLen = signature.length;
      offset += writeInt(sigLen, res, offset, 2);
      System.arraycopy(signature, 0, res, offset, sigLen);
      return res;
    }

  } // class DigitallySigned

  /**
   * <pre>
   * opaque SerializedSCT&lt;1..2^16-1&gt;;
   * </pre>
   */
  public static class SerializedSCT {

    private final List<SignedCertificateTimestamp> scts;

    public static SerializedSCT getInstance(byte[] encoded) {
      int length = readInt2(encoded, 0);
      if (2 + length != encoded.length) {
        throw new IllegalArgumentException("length unmatch");
      }

      List<SignedCertificateTimestamp> scts = new LinkedList<>();

      AtomicInteger offsetObj = new AtomicInteger(2);
      while (offsetObj.get() < encoded.length) {
        int sctLen = readInt2(encoded, offsetObj.getAndAdd(2));
        SignedCertificateTimestamp sct = SignedCertificateTimestamp.getInstance(encoded, offsetObj, sctLen);
        scts.add(sct);
      }

      return new SerializedSCT(scts);
    }

    public SerializedSCT(List<SignedCertificateTimestamp> scts) {
      this.scts = scts == null ? new LinkedList<>() : new LinkedList<>(scts);
    }

    public int size() {
      return scts.size();
    }

    public SignedCertificateTimestamp get(int index) {
      return scts.get(index);
    }

    public SignedCertificateTimestamp remove(int index) {
      return scts.remove(index);
    }

    public void add(SignedCertificateTimestamp sct) {
      scts.add(sct);
    }

    public byte[] getEncoded() {
      if (scts.isEmpty()) {
        return new byte[] {0, 0};
      }

      List<byte[]> encodedScts = new ArrayList<>(scts.size());
      int totalLen = 0;
      for (SignedCertificateTimestamp sct : scts) {
        byte[] encodedSct = sct.getEncoded();
        // the serialized SCT will be included. Although the maximal length is
        // not defined in RFC 6962, the log servers use 2 bytes to represent
        // the length.
        byte[] encodedSctWithLen = new byte[2 + encodedSct.length];
        writeInt(encodedSct.length, encodedSctWithLen, 0, 2);
        System.arraycopy(encodedSct, 0, encodedSctWithLen, 2, encodedSct.length);
        totalLen += encodedSctWithLen.length;
        encodedScts.add(encodedSctWithLen);
      }

      byte[] res = new byte[2 + totalLen];
      int offset = writeInt(totalLen, res, 0, 2);
      for (byte[] m : encodedScts) {
        System.arraycopy(m, 0, res, offset, m.length);
        offset += m.length;
      }

      return res;
    } // class getEncoded

  } // class SerializedSCT

  public enum HashAlgorithm {
    none((byte) 0),
    md5((byte) 1),
    sha1((byte) 2),
    sha224((byte) 3),
    sha256((byte) 4),
    sha384((byte) 5),
    sha512((byte) 6);

    private final byte code;

    HashAlgorithm(byte code) {
      this.code = code;
    }

    public byte getCode() {
      return code;
    }

    public static HashAlgorithm ofCode(byte code) {
      for (HashAlgorithm m : values()) {
        if (m.code == code) {
          return m;
        }
      }
      return null;
    }
  } // class HashAlgorithm

  public enum SignatureAlgorithm {
    anonymous((byte) 0),
    rsa((byte) 1),
    dsa((byte) 2),
    ecdsa((byte) 3);

    private final byte code;

    SignatureAlgorithm(byte code) {
      this.code = code;
    }

    public byte getCode() {
      return code;
    }

    public static SignatureAlgorithm ofCode(byte code) {
      for (SignatureAlgorithm m : values()) {
        if (m.code == code) {
          return m;
        }
      }
      return null;
    }
  } // class SignatureAlgorithm

  /**
   * ASN.1 definition:
   * <pre>
   * struct {
   *     HashAlgorithm hash;
   *     SignatureAlgorithm signature;
   * } SignatureAndHashAlgorithm;
   * </pre>
   */
  public static class SignatureAndHashAlgorithm {

    private final HashAlgorithm hash;

    private final SignatureAlgorithm signature;

    public static SignatureAndHashAlgorithm getInstance(byte[] encoded) {
      return new SignatureAndHashAlgorithm(HashAlgorithm.ofCode(encoded[0]), SignatureAlgorithm.ofCode(encoded[1]));
    }

    public SignatureAndHashAlgorithm(HashAlgorithm hash, SignatureAlgorithm signature) {
      this.hash = notNull(hash, "hash");
      this.signature = notNull(signature, "signature");
    }

    public HashAlgorithm getHash() {
      return hash;
    }

    public SignatureAlgorithm getSignature() {
      return signature;
    }

    public byte[] getEncoded() {
      return new byte[] {hash.getCode(), signature.getCode()};
    }

  } // class SignatureAndHashAlgorithm

  /**
   * ASN1. definition:
   * <pre>
   * struct {
   *     Version sct_version;
   *     LogID id;
   *     uint64 timestamp;
   *     CtExtensions extensions;
   *     DigitallySigned signature
   *  } SignedCertificateTimestamp
   * </pre>
   */
  public static class SignedCertificateTimestamp {

    /**
     * ASN.1 definition:
     * <pre>
     * enum { v1(0), (255) }
     *   Version;
     * </pre>
     */
    private final byte version;

    /**
     * ASN.1 definition:
     * <pre>
     * struct {
     *     opaque key_id[32];
     * } LogID;
     * </pre>
     */
    private final byte[] logId;

    /**
     * ASN.1 definition:
     * <pre>
     * uint64 timestamp;
     * </pre>
     */
    private final long timestamp;

    /**
     * ASN.1 definition:
     * <pre>
     * opaque CtExtensions<0..2^16-1>;
     * CtExtensions extensions.
     * </pre>
     * Does not contain the encoded length.
     */
    private final byte[] extensions;

    private final DigitallySigned digitallySigned;

    public static SignedCertificateTimestamp getInstance(byte[] encoded, AtomicInteger offsetObj, int len) {
      int startOffset = offsetObj.get();
      int offset = startOffset;
      byte version = encoded[offset++];
      byte[] logID = copyOf(encoded, offset, 32);
      offset += 32;

      long timestamp = Pack.bigEndianToLong(encoded, offset);
      offset += 8;

      int extensionsLen = readInt2(encoded, offset);
      offset += 2;

      byte[] extensions = (extensionsLen == 0) ? new byte[0] : copyOf(encoded, offset, extensionsLen);
      offset += extensionsLen;

      offsetObj.set(offset);

      DigitallySigned digitallySigned = DigitallySigned.getInstance(encoded, offsetObj);

      if (offsetObj.get() != startOffset + len) {
        throw new IllegalArgumentException("length unmatch");
      }

      return new SignedCertificateTimestamp(version, logID, timestamp, extensions, digitallySigned);
    } // constructor

    public SignedCertificateTimestamp(
        byte version, byte[] logId, long timestamp, byte[] extensions, DigitallySigned digitallySigned) {
      this.version = version;
      notNull(logId, "logId");
      Args.equals(logId.length, "logID.length", 32);
      this.logId = logId;
      this.timestamp = timestamp;
      this.extensions = extensions == null ? new byte[0] : extensions;
      this.digitallySigned = notNull(digitallySigned, "digitallySigned");
    }

    public int getVersion() {
      return version;
    }

    public byte[] getLogId() {
      return Arrays.copyOf(logId, logId.length);
    }

    public long getTimestamp() {
      return timestamp;
    }

    public byte[] getExtensions() {
      return extensions.length == 0 ? extensions : Arrays.copyOf(extensions, extensions.length);
    }

    public DigitallySigned getDigitallySigned() {
      return digitallySigned;
    }

    public byte[] getEncoded() {
      byte[] encodedDs = digitallySigned.getEncoded();
      int totoalLen = 41 + 2 + extensions.length + encodedDs.length; //41: 1 + 32 + 8, 2:  length of extensions

      byte[] res = new byte[totoalLen];
      int offset = 0;
      // version: 1 bytes
      res[offset++] = version;

      // logID: 32 bytes
      System.arraycopy(logId, 0, res, 1, logId.length);
      offset += logId.length;

      // timestamp: 8 bytes
      byte[] tsBytes = Pack.longToBigEndian(timestamp);
      System.arraycopy(tsBytes, 0, res, offset, 8);
      offset += 8;

      // extensions
      offset += writeInt(extensions.length, res, offset, 2);
      if (extensions.length > 0) {
        System.arraycopy(extensions, 0, res, offset, extensions.length);
        offset += extensions.length;
      }

      System.arraycopy(encodedDs, 0, res, offset, encodedDs.length);
      return res;
    } // method getEncoded

  } // class SignedCertificateTimestamp

  /**
   * <pre>
   * struct {
   *     SerializedSCT sct_list &lt;1..2^16-1&gt;;
   * } SignedCertificateTimestampList;
   * </pre>
   */
  public static class SignedCertificateTimestampList {

    private final SerializedSCT sctList;

    public static SignedCertificateTimestampList getInstance(byte[] encoded) {
      SerializedSCT sctList = SerializedSCT.getInstance(encoded);
      return new SignedCertificateTimestampList(sctList);
    }

    public SignedCertificateTimestampList(SerializedSCT sctList) {
      this.sctList = notNull(sctList, "sctList");
    }

    public SerializedSCT getSctList() {
      return sctList;
    }

    public byte[] getEncoded() {
      return sctList.getEncoded();
    }

  } // class SignedCertificateTimestampList

  /**
   * Write integer value to the buffer.
   * @param value integer value to be written.
   * @param buffer buffer
   * @param offset offset of the buffer
   * @param bytesLenOfValue number of bytes to represent the length, between 1 and 4.
   * @return bytesLenOfLength
   */
  private static int writeInt(int value, byte[] buffer, int offset, int bytesLenOfValue) {
    if (bytesLenOfValue == 4) {
      buffer[offset++] = (byte) (value >>> 24);
    }

    if (bytesLenOfValue >= 3) {
      buffer[offset++] = (byte) (value >>> 16);
    }

    if (bytesLenOfValue >= 2) {
      buffer[offset++] = (byte) (value >>> 8);
    }

    buffer[offset] = (byte)  value;
    return bytesLenOfValue;
  } // method writeInt

  /**
   * Read integer value from the buffer (2 bytes).
   * @param buffer buffer
   * @param offset offset of the buffer
   * @return bytesLenOfLength
   */
  private static int readInt2(byte[] buffer, int offset) {
    return ((0xFF & buffer[offset]) << 8) | (0xFF & buffer[offset + 1]);
  } // method readInt

  private static byte[] copyOf(byte[] original, int from, int len) {
    return Arrays.copyOfRange(original, from, from + len);
  }

  public static void update(
      Signature sig, byte version, long timestamp, byte[] sctExtensions, byte[] issuerKeyHash, byte[] preCertTbsCert)
      throws SignatureException {
    sig.update(version);
    sig.update((byte) 0); // signature_type = certificate_timestamp
    byte[] timestampBytes = Pack.longToBigEndian(timestamp);
    sig.update(timestampBytes); // timestamp
    sig.update(new byte[] {0, 1}); // LogEntryType: precert_entry(1)
    sig.update(issuerKeyHash);

    int len = preCertTbsCert.length;
    sig.update(encodeLength(len, 3));
    sig.update(preCertTbsCert);

    len = sctExtensions == null ? 0 : sctExtensions.length;
    sig.update(encodeLength(len, 2));
    if (len > 0) {
      sig.update(sctExtensions);
    }
  }

  public static byte[] getPreCertTbsCert(TBSCertificate tbsCert) throws IOException {
    ASN1EncodableVector vec = new ASN1EncodableVector();
    ASN1Sequence tbs = (ASN1Sequence) tbsCert.toASN1Primitive();

    // version, serialNumber, signature (algorithm), issuer, validity, subject, subjectpublickeyinfo
    for (int i = 0; i < 7; i++) {
      vec.add(tbs.getObjectAt(i));
    }

    ASN1TaggedObject taggedExtns = (ASN1TaggedObject) tbs.getObjectAt(7);
    int tagNo = taggedExtns.getTagNo();

    ASN1Sequence extns = (ASN1Sequence) taggedExtns.getBaseObject().toASN1Primitive();
    ASN1EncodableVector extnsVec = new ASN1EncodableVector(extns.size() - 1);
    final int size = extns.size();
    for (int i = 0; i < size; i++) {
      ASN1Encodable extn = extns.getObjectAt(i).toASN1Primitive();
      ASN1Encodable type = ((ASN1Sequence) extn).getObjectAt(0);
      if (ObjectIdentifiers.Extn.id_precertificate.equals(type) || ObjectIdentifiers.Extn.id_SCTs.equals(type)) {
        continue;
      }

      extnsVec.add(extn);
    }

    vec.add(new DERTaggedObject(true, tagNo, new DERSequence(extnsVec)));
    return new DERSequence(vec).getEncoded();
  }

  private static byte[] encodeLength(int length, int lengthBytes) {
    byte[] encoded = new byte[lengthBytes];
    writeInt(length, encoded, 0, lengthBytes);
    return encoded;
  }

}
