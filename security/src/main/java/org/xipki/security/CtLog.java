/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.Pack;
import org.xipki.util.Args;

/**
 * RFC 6962 implementation of the required classes for the extension SCT in certificate.
 *
 * @author Lijun Liao
 */
public class CtLog {

  /**
   * struct {
   *     SignatureAndHashAlgorithm algorithm;
   *     opaque signature<0..2^16-1>;
   * } DigitallySigned;
   *
   */
  public static class DigitallySigned {

    private final SignatureAndHashAlgorithm algorithm;

    private final byte[] signature;

    public static DigitallySigned getInstance(byte[] encoded, AtomicInteger offsetObj) {
      int offset = offsetObj.get();

      SignatureAndHashAlgorithm algorithm =
          SignatureAndHashAlgorithm.getInstance(copyOf(encoded, offset, 2));
      offset += 2;

      int signatureLen = readInt(encoded, offset, 2);
      offset += 2;
      byte[] signature = copyOf(encoded, offset, signatureLen);
      offset += signatureLen;

      offsetObj.set(offset);

      return new DigitallySigned(algorithm, signature);
    }

    public DigitallySigned(SignatureAndHashAlgorithm algorithm, byte[] signature) {
      this.algorithm = Args.notNull(algorithm, "algorithm");
      this.signature = Args.notNull(signature, "signature");
    }

    public SignatureAndHashAlgorithm getAlgorithm() {
      return algorithm;
    }

    public byte[] getSignature() {
      return Arrays.copyOf(signature, signature.length);
    }

    public Object getSignatureObject() {
      switch (algorithm.signature) {
        case ecdsa:
        case dsa:
          ASN1Sequence seq = ASN1Sequence.getInstance(signature);
          return new BigInteger[] {
              ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue(),
              ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue()};
        case rsa:
          return signature;
        case anonymous:
          return signature;
        default:
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

  }

  /**
   * opaque SerializedSCT<1..2^16-1>;
   *
   */
  // CHECKSTYLE:SKIP
  public static class SerializedSCT {

    private final List<SignedCertificateTimestamp> scts;

    public static SerializedSCT getInstance(byte[] encoded) {
      int length = readInt(encoded, 0, 2);
      if (2 + length != encoded.length) {
        throw new IllegalArgumentException("length unmatch");
      }

      List<SignedCertificateTimestamp> scts = new LinkedList<>();

      AtomicInteger offsetObj = new AtomicInteger(2);
      while (offsetObj.get() < encoded.length) {
        int sctLen = readInt(encoded, offsetObj.getAndAdd(2), 2);
        SignedCertificateTimestamp sct = SignedCertificateTimestamp.getInstance(
            encoded, offsetObj, sctLen);
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
      if (scts == null || scts.isEmpty()) {
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
    }

  }

  public static enum HashAlgorithm {
    none((byte) 0),
    md5((byte) 1),
    sha1((byte) 2),
    sha224((byte) 3),
    sha256((byte) 4),
    sha384((byte) 5),
    sha512((byte) 6);

    private byte code;

    private HashAlgorithm(byte code) {
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
  }

  public static enum SignatureAlgorithm {
    anonymous((byte) 0),
    rsa((byte) 1),
    dsa((byte) 2),
    ecdsa((byte) 3);

    private byte code;

    private SignatureAlgorithm(byte code) {
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
  }

  /**
   * struct {
   *     HashAlgorithm hash;
   *     SignatureAlgorithm signature;
   * } SignatureAndHashAlgorithm;
   *
   */
  public static class SignatureAndHashAlgorithm {

    private final HashAlgorithm hash;

    private final SignatureAlgorithm signature;

    public static SignatureAndHashAlgorithm getInstance(byte[] encoded) {
      return new SignatureAndHashAlgorithm(
          HashAlgorithm.ofCode(encoded[0]),
          SignatureAlgorithm.ofCode(encoded[1]));
    }

    public SignatureAndHashAlgorithm(HashAlgorithm hash, SignatureAlgorithm signature) {
      this.hash = Args.notNull(hash, "hash");
      this.signature = Args.notNull(signature, "signature");
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

  }

  /**
   * struct {
   *     Version sct_version;
   *     LogID id;
   *     uint64 timestamp;
   *     CtExtensions extensions;
   *     DigitallySigned signature
   *  } SignedCertificateTimestamp
   *
   */
  public static class SignedCertificateTimestamp {

    /**
     * enum { v1(0), (255) }
     *   Version;
     */
    private final byte version;

    /**
     * struct {
     *     opaque key_id[32];
     * } LogID;
     */
    private final byte[] logId;

    /**
     * uint64 timestamp;
     */
    private final long timestamp;

    /**
     * opaque CtExtensions<0..2^16-1>;
     * CtExtensions extensions.
     *
     * Does not contain the encoded length.
     */
    private final byte[] extensions;

    private final DigitallySigned digitallySigned;

    public static SignedCertificateTimestamp getInstance(byte[] encoded, AtomicInteger offsetObj,
        int len) {
      int startOffset = offsetObj.get();
      int offset = startOffset;
      byte version = encoded[offset++];
      byte[] logID = copyOf(encoded, offset, 32);
      offset += 32;

      long timestamp = Pack.bigEndianToLong(encoded, offset);
      offset += 8;

      int extensionsLen = readInt(encoded, offset, 2);
      offset += 2;
      byte[] extensions;
      if (extensionsLen == 0) {
        extensions = new byte[0];
      } else {
        extensions = copyOf(encoded, offset, extensionsLen);
        offset += extensionsLen;
      }

      offsetObj.set(offset);

      DigitallySigned digitallySigned = DigitallySigned.getInstance(encoded, offsetObj);

      if (offsetObj.get() != startOffset + len) {
        throw new IllegalArgumentException("length unmatch");
      }

      return new SignedCertificateTimestamp(version, logID, timestamp, extensions, digitallySigned);
    }

    public SignedCertificateTimestamp(byte version, byte[] logId, long timestamp, byte[] extensions,
        DigitallySigned digitallySigned) {
      this.version = version;
      Args.notNull(logId, "logId");
      Args.equals(logId.length, "logID.length", 32);
      this.logId = logId;
      this.timestamp = timestamp;
      this.extensions = extensions == null ? new byte[0] : extensions;
      this.digitallySigned = Args.notNull(digitallySigned, "digitallySigned");
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
      int totoalLen = 41 //37 = 1 + 32 + 8
          + 2 // length of extensions
          + extensions.length
          + encodedDs.length;

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
    }

  }

  /**
   * struct {
   *     SerializedSCT sct_list <1..2^16-1>;
   * } SignedCertificateTimestampList;
   *
   */
  public static class SignedCertificateTimestampList {

    private final SerializedSCT sctList;

    public static SignedCertificateTimestampList getInstance(byte[] encoded) {
      SerializedSCT sctList = SerializedSCT.getInstance(encoded);
      return new SignedCertificateTimestampList(sctList);
    }

    public SignedCertificateTimestampList(SerializedSCT sctList) {
      this.sctList = Args.notNull(sctList, "sctList");
    }

    public SerializedSCT getSctList() {
      return sctList;
    }

    public byte[] getEncoded() {
      return sctList.getEncoded();
    }

  }

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
      buffer[offset]     = (byte) (value >>> 24);
      buffer[offset + 1] = (byte) (value >>> 16);
      buffer[offset + 2] = (byte) (value >>> 8);
      buffer[offset + 3] = (byte)  value;
    } else if (bytesLenOfValue == 3) {
      buffer[offset]     = (byte) (value >>> 16);
      buffer[offset + 1] = (byte) (value >>> 8);
      buffer[offset + 2] = (byte)  value;
    } else if (bytesLenOfValue == 2) {
      buffer[offset]     = (byte) (value >>> 8);
      buffer[offset + 1] = (byte)  value;
    } else {
      buffer[offset]     = (byte)  value;
    }

    return bytesLenOfValue;
  }

  /**
   * Read integer value from the buffer.
   * @param buffer buffer
   * @param offset offset of the buffer
   * @param bytesLenOfValue number of bytes to represent the length, between 1 and 4.
   * @return bytesLenOfLength
   */
  private static int readInt(byte[] buffer, int offset, int bytesLenOfValue) {
    if (bytesLenOfValue == 4) {
      return (0xFF & buffer[offset]   ) << 24
          | (0xFF & buffer[offset + 1]) << 16
          | (0xFF & buffer[offset + 2]) << 8
          | (0xFF & buffer[offset + 3]);
    } else if (bytesLenOfValue == 3) {
      return  (0xFF & buffer[offset]  ) << 16
          | (0xFF & buffer[offset + 1]) << 8
          | (0xFF & buffer[offset + 2]);
    } else if (bytesLenOfValue == 2) {
      return  (0xFF & buffer[offset]  ) << 8
          | (0xFF & buffer[offset + 1]);
    } else {
      return 0xFF & buffer[offset];
    }
  }

  private static byte[] copyOf(byte[] original, int from, int len) {
    return Arrays.copyOfRange(original, from, from + len);
  }

}
