// Copyright (c) 2013-2023 xipki. All rights reserved.
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

public class UnsuspendOrRemoveRequest extends CaIdentifierRequest {

  private final BigInteger[] entries;

  public UnsuspendOrRemoveRequest(byte[] issuerCertSha1Fp, X500NameType issuer,
                                  byte[] authorityKeyIdentifier, BigInteger[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.entries = entries;
  }

  public BigInteger[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    super.encode0(encoder, 1);
    encoder.writeBigInts(entries);
  }

  public static UnsuspendOrRemoveRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("UnsuspendOrRemoveRequest", decoder, 3 + 1); // 3 fields defined in the pararent class.
      return new UnsuspendOrRemoveRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          decoder.readBigInts());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, UnsuspendOrRemoveRequest.class), ex);
    }
  }

}
