// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncodable;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EnrollOrPullCertResponseEntry implements CborEncodable {

  private final BigInteger id;

  private final ErrorEntry error;

  private final byte[] cert;

  private final byte[] privateKey;

  public EnrollOrPullCertResponseEntry(BigInteger id, ErrorEntry error, byte[] cert, byte[] privateKey) {
    this.id = id;
    this.error = error;
    this.cert = cert;
    this.privateKey = privateKey;
  }

  public BigInteger getId() {
    return id;
  }

  public ErrorEntry getError() {
    return error;
  }

  public byte[] getCert() {
    return cert;
  }

  public byte[] getPrivateKey() {
    return privateKey;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(4);
      encoder.writeByteString(id);
      encoder.writeObject(error);
      encoder.writeByteString(cert);
      encoder.writeByteString(privateKey);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static EnrollOrPullCertResponseEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(4)) {
        return null;
      }

      return new EnrollOrPullCertResponseEntry(
          decoder.readBigInt(),
          ErrorEntry.decode(decoder),
          decoder.readByteString(),
          decoder.readByteString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + EnrollOrPullCertResponseEntry.class.getName(), ex);
    }
  }

  public static EnrollOrPullCertResponseEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(EnrollOrPullCertResponseEntry[].class);
    if (arrayLen == null) {
      return null;
    }

    EnrollOrPullCertResponseEntry[] entries = new EnrollOrPullCertResponseEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = EnrollOrPullCertResponseEntry.decode(decoder);
    }

    return entries;
  }

}
