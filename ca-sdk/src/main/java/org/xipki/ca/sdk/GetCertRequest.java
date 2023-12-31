// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
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
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(2);
    encoder.writeBigInt(serialNumber);
    encoder.writeObject(issuer);
  }

  public static GetCertRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("GetCertRequest", decoder, 2);
      return new GetCertRequest(
          decoder.readBigInt(),
          X500NameType.decode(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, GetCertRequest.class), ex);
    }
  }

}
