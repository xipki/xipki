// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.CompareUtil;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Issuer in the OCSP request.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class RequestIssuer {

  private final HashAlgo hashAlgo;

  private final byte[] data;

  private final int from;

  private final int nameHashFrom;

  private final int length;

  public RequestIssuer(HashAlgo hashAlgo, byte[] hashData) {
    int algIdLen = 2 + hashAlgo.getEncodedLength() + 2;
    data = new byte[algIdLen + hashData.length];
    int offset = 0;
    data[offset++] = 0x30;
    data[offset++] = (byte) (hashAlgo.getEncodedLength() + 2);
    offset += hashAlgo.write(data, offset);
    data[offset++] = 0x05;
    data[offset++] = 0x00;

    this.nameHashFrom = offset;

    System.arraycopy(hashData, 0, data, offset, hashData.length);
    offset += hashData.length;

    this.from = 0;
    this.length = offset;
    this.hashAlgo = hashAlgo;
  } // constructor

  public RequestIssuer(byte[] data) throws NoSuchAlgorithmException {
    this(data, 0, data.length);
  } // constructor

  public RequestIssuer(byte[] data, int from, int length)
      throws NoSuchAlgorithmException {
    this.data = data;
    this.from = from;
    this.length = length;
    this.hashAlgo = HashAlgo.getInstanceForEncoded(data, from + 2,
        2 + data[from + 3]);

    int hashAlgoFieldLen = 0xFF & data[from + 1];
    this.nameHashFrom = from + 2 + hashAlgoFieldLen;
  } // constructor

  public static int arraycopy(byte[] hashData, byte[] data, int offset) {
    System.arraycopy(hashData, 0, data, offset, hashData.length);
    return hashData.length;
  }

  public HashAlgo hashAlgorithm() {
    return hashAlgo;
  }

  public String hashAlgorithmOID() {
    if (hashAlgo != null) {
      return hashAlgo.getOid().getId();
    } else {
      final int start = from + 2;
      byte[] bytes = Arrays.copyOfRange(data, start,
          start + 2 + (0xFF & data[from + 3]));
      return ASN1ObjectIdentifier.getInstance(bytes).getId();
    }
  }

  public int getFrom() {
    return from;
  }

  public byte[] getData() {
    return data;
  }

  public int getNameHashFrom() {
    return nameHashFrom;
  }

  public int getLength() {
    return length;
  }

  public int write(byte[] out, int offset) {
    System.arraycopy(data, from, out, offset, length);
    return length;
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof RequestIssuer)) {
      return false;
    }

    RequestIssuer other = (RequestIssuer) obj;
    return (this.length == other.length)
        && CompareUtil.areEqual(this.data, this.from,
            other.data, other.from, this.length);
  }

  @Override
  public String toString() {
    return Hex.encode(Arrays.copyOfRange(data, from, from + length));
  }

}
