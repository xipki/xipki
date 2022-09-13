package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

/**
 *
 * @author Lijun Liao
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
    return JSON.parseObject(encoded, CertprofileInfoRequest.class);
  }

}
