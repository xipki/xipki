// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * Unsuspend Or Remove Certs Request payload.
 *
 * @author Lijun Liao (xipki)
 */
public class UnsuspendOrRemoveCertsRequest extends CaIdentifierRequest {

  private final BigInteger[] entries;

  public UnsuspendOrRemoveCertsRequest(byte[] issuerCertSha1Fp, X500NameType issuer,
                                      byte[] authorityKeyIdentifier, BigInteger[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.entries = entries;
  }

  public BigInteger[] entries() {
    return entries;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    int start = buf.length();
    toStringCaIdentifier(buf, indentLevel);
    if (entries != null) {
      ToStringUtil.appendIndent(buf, indentLevel, "entries:\n");
      for (BigInteger entry : entries) {
        appendBigInt(buf, indentLevel + 1, "-", entry);
      }
    }

    return endToString(buf, indentLevel, start);
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    super.encode0(encoder, 1);
    encoder.writeBigInts(entries);
  }

  public static UnsuspendOrRemoveCertsRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      // 3 fields defined in the parent class.
      assertArrayStart("UnsuspendOrRemoveRequest", decoder, 3 + 1);
      return new UnsuspendOrRemoveCertsRequest(decoder.readByteString(),
          X500NameType.decode(decoder), decoder.readByteString(), decoder.readBigInts());
    } catch (RuntimeException ex) {
      throw new CodecException(buildDecodeErrMessage(ex, UnsuspendOrRemoveCertsRequest.class), ex);
    }
  }

}
