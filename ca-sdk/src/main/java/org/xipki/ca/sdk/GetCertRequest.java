// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.ByteArrayInputStream;
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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeByteString(serialNumber);
      encoder.writeObject(issuer);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static GetCertRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new GetCertRequest(
          decoder.readBigInt(),
          X500NameType.decode(decoder));
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + GetCertRequest.class.getName(), ex);
    }
  }

}
