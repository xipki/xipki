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
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class RevokeCertsRequest extends CaIdentifierRequest {

  private final RevokeCertRequestEntry[] entries;

  public RevokeCertsRequest(byte[] issuerCertSha1Fp, X500NameType issuer,
                            byte[] authorityKeyIdentifier, RevokeCertRequestEntry[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.entries = entries;
  }

  public RevokeCertRequestEntry[] getEntries() {
    return entries;
  }

  public void encode(CborEncoder encoder) throws EncodeException {
    super.encode(encoder, 1);
    try {
      encoder.writeObjects(entries);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static RevokeCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("RevokeCertsRequest", decoder, 4);
      return new RevokeCertsRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          RevokeCertRequestEntry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + RevokeCertsRequest.class.getName(), ex);
    }
  }

}
