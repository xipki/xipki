// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.CBOR;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertprofileInfoRequest extends SdkRequest {

  private String profile;

  public String getProfile() {
    return profile;
  }

  public void setProfile(String profile) {
    this.profile = profile;
  }

  public static CertprofileInfoRequest decode(byte[] encoded) {
    return CBOR.parseObject(encoded, CertprofileInfoRequest.class);
  }

}
