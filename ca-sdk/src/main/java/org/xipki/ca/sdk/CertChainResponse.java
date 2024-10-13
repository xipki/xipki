// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;

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
  protected void encode0(CborEncoder encoder) throws IOException {
    encoder.writeArrayStart(1);
    encoder.writeByteStrings(certificates);
  }

  public static CertChainResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CertChainResponse", decoder, 1);
      return new CertChainResponse(decoder.readByteStrings());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, CertChainResponse.class), ex);
    }
  }

}
