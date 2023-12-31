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
import java.time.Instant;

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
  private final Instant thisUpdate;

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GetCRLRequest(BigInteger crlNumber, Instant thisUpdate, String crlDp) {
    this.crlNumber = crlNumber;
    this.thisUpdate = thisUpdate;
    this.crlDp = crlDp;
  }

  public BigInteger getCrlNumber() {
    return crlNumber;
  }

  public Instant getThisUpdate() {
    return thisUpdate;
  }

  public String getCrlDp() {
    return crlDp;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(3);
    encoder.writeBigInt(crlNumber);
    encoder.writeInstant(thisUpdate);
    encoder.writeTextString(crlDp);
  }

  public static GetCRLRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("GetCRLRequest", decoder, 3);
      return new GetCRLRequest(
          decoder.readBigInt(),
          decoder.readInstant(),
          decoder.readTextString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, GetCRLRequest.class), ex);
    }
  }

}
