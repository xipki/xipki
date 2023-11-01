// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeByteStrings(certificates);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static CertChainResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CertChainResponse", decoder, 1);
      return new CertChainResponse(decoder.readByteStrings());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + CertChainResponse.class.getName(), ex);
    }
  }

}
