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

public class EnrollCertsRequest extends SdkRequest {

  private String transactionId;

  /**
   * For case to enroll more than 1 certificates in one request, default to false.
   * <ul>
   *   <li>true: either all certificates have been enrolled or failed.</li>
   *   <li>false: each certificate may have been enrolled or failed</li>
   * </ul>
   */
  private Boolean groupEnroll;

  /**
   * Whether an explicit confirm is required. Default to false.
   */
  private Boolean explicitConfirm;

  private Integer confirmWaitTimeMs;

  /**
   * Specifies how to embed the CA certificate in the response:
   */
  private CertsMode caCertMode;

  private EnrollCertRequestEntry[] entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Boolean getGroupEnroll() {
    return groupEnroll;
  }

  public void setGroupEnroll(Boolean groupEnroll) {
    this.groupEnroll = groupEnroll;
  }

  public Boolean getExplicitConfirm() {
    return explicitConfirm;
  }

  public void setExplicitConfirm(Boolean explicitConfirm) {
    this.explicitConfirm = explicitConfirm;
  }

  public Integer getConfirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public void setConfirmWaitTimeMs(Integer confirmWaitTimeMs) {
    this.confirmWaitTimeMs = confirmWaitTimeMs;
  }

  public CertsMode getCaCertMode() {
    return caCertMode;
  }

  public void setCaCertMode(CertsMode caCertMode) {
    this.caCertMode = caCertMode;
  }

  public EnrollCertRequestEntry[] getEntries() {
    return entries;
  }

  public void setEntries(EnrollCertRequestEntry[] entries) {
    this.entries = entries;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(6);
      encoder.writeTextString(transactionId);
      encoder.writeBooleanObj(groupEnroll);
      encoder.writeBooleanObj(explicitConfirm);
      encoder.writeIntObj(confirmWaitTimeMs);
      encoder.writeEnumObj(caCertMode);
      encoder.writeObjects(entries);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static EnrollCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("EnrollCertsRequest", decoder, 6);
      EnrollCertsRequest ret = new EnrollCertsRequest();
      ret.setTransactionId(decoder.readTextString());
      ret.setGroupEnroll(decoder.readBooleanObj());
      ret.setExplicitConfirm(decoder.readBooleanObj());
      ret.setConfirmWaitTimeMs(decoder.readIntObj());
      String str = decoder.readTextString();
      if (str != null) {
        ret.setCaCertMode(CertsMode.valueOf(str));
      }
      ret.setEntries(EnrollCertRequestEntry.decodeArray(decoder));
      return ret;
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + EnrollCertsRequest.class.getName(), ex);
    }
  }

}
