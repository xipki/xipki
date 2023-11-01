// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

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
      encoder.writeBigInt(serialNumber);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
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
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + OldCertInfoByIssuerAndSerial.class.getName(), ex);
    }
  }

}
