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

import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ConfirmCertsRequest extends SdkRequest {

  private String transactionId;

  private List<ConfirmCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<ConfirmCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<ConfirmCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static ConfirmCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, ConfirmCertsRequest.class);
  }

}
