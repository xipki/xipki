// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class GetCRLRequest extends SdkRequest {

  /**
   * Returns CRL of this specified crlNumber.
   */
  private final BigInteger crlNumber;

  /**
   * Epoch time in seconds of thisUpdate of the known CRL.
   * If present, returns only CRL with larger thisUpdate.
   */
  private final Long thisUpdate;

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GetCRLRequest(BigInteger crlNumber, Long thisUpdate, String crlDp) {
    this.crlNumber = crlNumber;
    this.thisUpdate = thisUpdate;
    this.crlDp = crlDp;
  }

  public BigInteger getCrlNumber() {
    return crlNumber;
  }

  public Long getThisUpdate() {
    return thisUpdate;
  }

  public String getCrlDp() {
    return crlDp;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeByteString(crlNumber);
      encoder.writeIntObj(thisUpdate);
      encoder.writeTextString(crlDp);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static GetCRLRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      return new GetCRLRequest(
          decoder.readBigInt(),
          decoder.readIntObj(),
          decoder.readTextString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + GetCRLRequest.class.getName(), ex);
    }
  }

}
