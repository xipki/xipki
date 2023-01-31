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

import org.xipki.security.util.JSON;

import java.util.List;

/**
 * Response for the operations enrolling certificates and polling certificates.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class EnrollOrPollCertsResponse extends SdkResponse {

  private String transactionId;

  private Long confirmWaitTime;

  private List<EnrollOrPullCertResponseEntry> entries;

  private List<byte[]> extraCerts;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<EnrollOrPullCertResponseEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<EnrollOrPullCertResponseEntry> entries) {
    this.entries = entries;
  }

  public List<byte[]> getExtraCerts() {
    return extraCerts;
  }

  public void setExtraCerts(List<byte[]> extraCerts) {
    this.extraCerts = extraCerts;
  }

  public Long getConfirmWaitTime() {
    return confirmWaitTime;
  }

  public void setConfirmWaitTime(Long confirmWaitTime) {
    this.confirmWaitTime = confirmWaitTime;
  }

  public static EnrollOrPollCertsResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, EnrollOrPollCertsResponse.class);
  }

}
