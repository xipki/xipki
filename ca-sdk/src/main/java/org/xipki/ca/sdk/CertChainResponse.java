// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 * Response containing the certificate chain.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertChainResponse extends SdkResponse {

  private final byte[][] certificates;

  public CertChainResponse(byte[][] certificates) {
    this.certificates = certificates;
  }

  public byte[][] getCertificates() {
    return certificates;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeByteStrings(certificates);
  }

  public static CertChainResponse decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CertChainResponse", decoder, 1);
      return new CertChainResponse(decoder.readByteStrings());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CertChainResponse.class), ex);
    }
  }

}
