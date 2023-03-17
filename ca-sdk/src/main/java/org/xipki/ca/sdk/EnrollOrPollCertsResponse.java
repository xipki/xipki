// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

import java.util.List;

/**
 * Response for the operations enrolling certificates and polling certificates.
 *
 * @author Lijun Liao (xipki)
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
