// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class GetCertRequest extends SdkRequest {

  /**
   * Serialnumber of the certificate.
   */
  private final BigInteger serialNumber;

  private final X500NameType issuer;

  public GetCertRequest(BigInteger serialNumber, X500NameType issuer) {
    this.serialNumber = serialNumber;
    this.issuer = issuer;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2).writeBigInt(serialNumber)
        .writeObject(issuer);
  }

  public static GetCertRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("GetCertRequest", decoder, 2);
      return new GetCertRequest(decoder.readBigInt(),
          X500NameType.decode(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, GetCertRequest.class), ex);
    }
  }

}
