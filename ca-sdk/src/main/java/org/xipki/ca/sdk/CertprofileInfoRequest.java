// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertprofileInfoRequest extends SdkRequest {

  private final String profile;

  public CertprofileInfoRequest(String profile) {
    this.profile = profile;
  }

  public String getProfile() {
    return profile;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeTextString(profile);
  }

  public static CertprofileInfoRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CertprofileInfoRequest", decoder, 1);
      return new CertprofileInfoRequest(decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CertprofileInfoRequest.class), ex);
    }
  }

}
