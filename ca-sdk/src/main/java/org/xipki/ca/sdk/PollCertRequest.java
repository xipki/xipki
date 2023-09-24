// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class PollCertRequest extends CaIdentifierRequest {

  private String transactionId;

  private PollCertRequestEntry[] entries;

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public void setEntries(PollCertRequestEntry[] entries) {
    this.entries = entries;
  }

  public String getTransactionId() {
    return transactionId;
  }

  public PollCertRequestEntry[] getEntries() {
    return entries;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      super.encode(encoder, 2);
      encoder.writeTextString(transactionId);
      encoder.writeObjects(entries);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static PollCertRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(5)) {
        return null;
      }

      PollCertRequest ret = new PollCertRequest();
      ret.setIssuerCertSha1Fp(decoder.readByteString());
      ret.setIssuer(X500NameType.decode(decoder));
      ret.setAuthorityKeyIdentifier(decoder.readByteString());
      ret.setTransactionId(decoder.readTextString());
      ret.setEntries(PollCertRequestEntry.decodeArray(decoder));
      return ret;
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + PollCertRequest.class.getName(), ex);
    }
  }

}
