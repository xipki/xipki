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

public class PollCertRequest extends CaIdentifierRequest {

  private final String transactionId;

  private final PollCertRequestEntry[] entries;

  public PollCertRequest(byte[] issuerCertSha1Fp, X500NameType issuer, byte[] authorityKeyIdentifier,
                         String transactionId, PollCertRequestEntry[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.transactionId = transactionId;
    this.entries = entries;
  }

  public String getTransactionId() {
    return transactionId;
  }

  public PollCertRequestEntry[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    super.encode0(encoder, 2);
    encoder.writeTextString(transactionId);
    encoder.writeObjects(entries);
  }

  public static PollCertRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("PollCertRequest", decoder, 5);
      return new PollCertRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          decoder.readTextString(),
          PollCertRequestEntry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, PollCertRequest.class), ex);
    }
  }

}
