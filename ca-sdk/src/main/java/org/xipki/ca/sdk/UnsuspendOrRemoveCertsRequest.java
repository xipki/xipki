// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class UnsuspendOrRemoveCertsRequest extends CaIdentifierRequest {

  private final BigInteger[] entries;

  public UnsuspendOrRemoveCertsRequest(
      byte[] issuerCertSha1Fp, X500NameType issuer,
      byte[] authorityKeyIdentifier, BigInteger[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.entries = entries;
  }

  public BigInteger[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    super.encode0(encoder, 1);
    encoder.writeBigInts(entries);
  }

  public static UnsuspendOrRemoveCertsRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      // 3 fields defined in the pararent class.
      assertArrayStart("UnsuspendOrRemoveRequest", decoder, 3 + 1);
      return new UnsuspendOrRemoveCertsRequest(decoder.readByteString(),
          X500NameType.decode(decoder), decoder.readByteString(),
          decoder.readBigInts());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, UnsuspendOrRemoveCertsRequest.class), ex);
    }
  }

}
