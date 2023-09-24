// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class OldCertInfoByIssuerAndSerial extends OldCertInfo {

  private final X500NameType issuer;

  /**
   * Uppercase hex encoded serialNumber.
   */
  private final BigInteger serialNumber;

  public OldCertInfoByIssuerAndSerial(boolean reusePublicKey, X500NameType issuer, BigInteger serialNumber) {
    super(reusePublicKey);
    this.issuer = issuer;
    this.serialNumber = serialNumber;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeBoolean(isReusePublicKey());
      encoder.writeObject(issuer);
      encoder.writeByteString(serialNumber);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static OldCertInfoByIssuerAndSerial decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      return new OldCertInfoByIssuerAndSerial(
          decoder.readBoolean(),
          X500NameType.decode(decoder),
          decoder.readBigInt());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + OldCertInfoByIssuerAndSerial.class.getName(), ex);
    }
  }

}
