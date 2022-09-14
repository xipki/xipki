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

public class PollCertRequest extends SdkRequest {

  private String transactionId;

  /**
   * SHA-1 fingerprint of the DER-encoded issuer's certificate
   */
  private byte[] issuerCertSha1Fp;

  private X500NameType issuer;

  private byte[] authorityKeyIdentifier;

  private List<PollCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  public void setIssuer(X500NameType issuer) {
    this.issuer = issuer;
  }

  public byte[] getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public byte[] getIssuerCertSha1Fp() {
    return issuerCertSha1Fp;
  }

  public void setIssuerCertSha1Fp(byte[] issuerCertSha1Fp) {
    this.issuerCertSha1Fp = issuerCertSha1Fp;
  }

  public List<PollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<PollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static PollCertRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, PollCertRequest.class);
  }

}
