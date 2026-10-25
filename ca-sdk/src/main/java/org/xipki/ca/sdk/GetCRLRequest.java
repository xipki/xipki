// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * Get CRLRequest payload.
 *
 * @author Lijun Liao (xipki)
 */
public class GetCRLRequest extends SdkRequest {

  /**
   * Returns CRL of this specified crlNumber.
   */
  private final Long crlNumber;

  /**
   * Epoch time in seconds of thisUpdate of the known CRL.
   * If present, returns only CRL with larger thisUpdate.
   */
  private final Instant thisUpdate;

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GetCRLRequest(Long crlNumber, Instant thisUpdate, String crlDp) {
    this.crlNumber = crlNumber;
    this.thisUpdate = thisUpdate;
    this.crlDp = crlDp;
  }

  public Long crlNumber() {
    return crlNumber;
  }

  public Instant thisUpdate() {
    return thisUpdate;
  }

  public String crlDp() {
    return crlDp;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(3).writeLongObj(crlNumber)
        .writeInstant(thisUpdate).writeTextString(crlDp);
  }

  public static GetCRLRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("GetCRLRequest", decoder, 3);
      return new GetCRLRequest(decoder.readLongObj(), decoder.readInstant(),
              decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(buildDecodeErrMessage(ex, GetCRLRequest.class), ex);
    }
  }

}
