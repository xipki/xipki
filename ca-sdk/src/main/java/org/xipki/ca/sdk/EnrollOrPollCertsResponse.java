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
 * Response for the operations enrolling certificates and polling certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EnrollOrPollCertsResponse extends SdkResponse {

  private String transactionId;

  private Long confirmWaitTime;

  private EnrollOrPullCertResponseEntry[] entries;

  private byte[][] extraCerts;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Long getConfirmWaitTime() {
    return confirmWaitTime;
  }

  public void setConfirmWaitTime(Long confirmWaitTime) {
    this.confirmWaitTime = confirmWaitTime;
  }

  public EnrollOrPullCertResponseEntry[] getEntries() {
    return entries;
  }

  public void setEntries(EnrollOrPullCertResponseEntry[] entries) {
    this.entries = entries;
  }

  public byte[][] getExtraCerts() {
    return extraCerts;
  }

  public void setExtraCerts(byte[][] extraCerts) {
    this.extraCerts = extraCerts;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(4);
      encoder.writeTextString(transactionId);
      encoder.writeIntObj(confirmWaitTime);
      encoder.writeObjects(entries);
      encoder.writeByteStrings(extraCerts);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static EnrollOrPollCertsResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("EnrollOrPollCertsResponse", decoder, 4);
      EnrollOrPollCertsResponse ret = new EnrollOrPollCertsResponse();
      ret.setTransactionId(decoder.readTextString());
      ret.setConfirmWaitTime(decoder.readLongObj());
      ret.setEntries(EnrollOrPullCertResponseEntry.decodeArray(decoder));
      ret.setExtraCerts(decoder.readByteStrings());
      return ret;
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + EnrollOrPollCertsResponse.class.getName(), ex);
    }
  }

}
