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

public class CertprofileInfoResponse extends SdkResponse {

  private final String[] requiredExtensionTypes;

  private final String[] optionalExtensionTypes;

  private final KeyType[] keyTypes;

  public CertprofileInfoResponse(String[] requiredExtensionTypes, String[] optionalExtensionTypes, KeyType[] keyTypes) {
    this.requiredExtensionTypes = requiredExtensionTypes;
    this.optionalExtensionTypes = optionalExtensionTypes;
    this.keyTypes = keyTypes;
  }

  public String[] getRequiredExtensionTypes() {
    return requiredExtensionTypes;
  }

  public String[] getOptionalExtensionTypes() {
    return optionalExtensionTypes;
  }

  public KeyType[] getKeyTypes() {
    return keyTypes;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeTextStrings(requiredExtensionTypes);
      encoder.writeTextStrings(optionalExtensionTypes);
      encoder.writeObjects(keyTypes);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static CertprofileInfoResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      return new CertprofileInfoResponse(
          decoder.readTextStrings(),
          decoder.readTextStrings(),
          KeyType.decodeArray(decoder));
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + CertprofileInfoResponse.class.getName(), ex);
    }
  }

}
