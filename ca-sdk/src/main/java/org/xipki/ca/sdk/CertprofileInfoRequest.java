// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;

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
  protected void encode0(CborEncoder encoder) throws IOException {
    encoder.writeArrayStart(1);
    encoder.writeTextString(profile);
  }

  public static CertprofileInfoRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CertprofileInfoRequest", decoder, 1);
      return new CertprofileInfoRequest(decoder.readTextString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, CertprofileInfoRequest.class), ex);
    }
  }

}
