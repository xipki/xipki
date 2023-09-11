// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertprofileInfoResponse extends SdkResponse {

  private String[] requiredExtensionTypes;

  private String[] optionalExtensionTypes;

  private KeyType[] keyTypes;

  public String[] getRequiredExtensionTypes() {
    return requiredExtensionTypes;
  }

  public void setRequiredExtensionTypes(String[] requiredExtensionTypes) {
    this.requiredExtensionTypes = requiredExtensionTypes;
  }

  public String[] getOptionalExtensionTypes() {
    return optionalExtensionTypes;
  }

  public void setOptionalExtensionTypes(String[] optionalExtensionTypes) {
    this.optionalExtensionTypes = optionalExtensionTypes;
  }

  public KeyType[] getKeyTypes() {
    return keyTypes;
  }

  public void setKeyTypes(KeyType[] keyTypes) {
    this.keyTypes = keyTypes;
  }

  public static CertprofileInfoResponse decode(byte[] encoded) {
    return CBOR.parseObject(encoded, CertprofileInfoResponse.class);
  }

}
