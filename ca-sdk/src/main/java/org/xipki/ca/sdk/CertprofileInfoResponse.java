/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

/**
 *
 * @author Lijun Liao
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
    return JSON.parseObject(encoded, CertprofileInfoResponse.class);
  }

}
