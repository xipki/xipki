// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.KeySpec;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertprofileInfoResponse extends SdkResponse {

  private final String[] requiredExtensionTypes;

  private final String[] optionalExtensionTypes;

  private final KeySpec[] keyTypes;

  public CertprofileInfoResponse(
      String[] requiredExtensionTypes, String[] optionalExtensionTypes,
      KeySpec[] keyTypes) {
    this.requiredExtensionTypes = requiredExtensionTypes;
    this.optionalExtensionTypes = optionalExtensionTypes;
    this.keyTypes = Args.notNull(keyTypes, "keyTypes");
  }

  public String[] getRequiredExtensionTypes() {
    return requiredExtensionTypes;
  }

  public String[] getOptionalExtensionTypes() {
    return optionalExtensionTypes;
  }

  public KeySpec[] getKeyTypes() {
    return keyTypes;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(3).writeTextStrings(requiredExtensionTypes)
        .writeTextStrings(optionalExtensionTypes);

    String[] keyTypeStrs = new String[keyTypes.length];
    for (int i = 0; i < keyTypes.length; i++) {
      keyTypeStrs[i] = keyTypes[i].name();
    }
    encoder.writeTextStrings(keyTypeStrs);
  }

  public static CertprofileInfoResponse decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CertprofileInfoResponse", decoder, 3);

      String[] requiredTypes = decoder.readTextStrings();
      String[] optionalTypes = decoder.readTextStrings();
      String[] keyTypeStrs   = decoder.readTextStrings();

      List<KeySpec> keyTypes = new ArrayList<>(keyTypeStrs.length);
      for (String keyTypeStr : keyTypeStrs) {
        KeySpec keyType;
        try {
          keyType = KeySpec.ofKeySpec(keyTypeStr);
        } catch (NoSuchAlgorithmException e) {
          throw new CodecException(e);
        }
        keyTypes.add(keyType);
      }

      return new CertprofileInfoResponse(requiredTypes, optionalTypes,
          keyTypes.toArray(new KeySpec[0]));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CertprofileInfoResponse.class), ex);
    }
  }

}
