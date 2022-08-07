/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.gateway.scep;

/**
 * SCEP control.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ScepControl {

  private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60; // 5 minutes

  private boolean includeCaCert = true;

  private boolean includeCertChain = false;

  private boolean includeSignerCert = true;

  private boolean supportGetCrl = false;

  private long maxSigningTimeBias = DFLT_MAX_SIGNINGTIME_BIAS;

  public boolean isIncludeCaCert() {
    return includeCaCert;
  }

  public void setIncludeCaCert(boolean includeCaCert) {
    this.includeCaCert = includeCaCert;
  }

  public boolean isIncludeCertChain() {
    return includeCertChain;
  }

  public void setIncludeCertChain(boolean includeCertChain) {
    this.includeCertChain = includeCertChain;
  }

  public boolean isIncludeSignerCert() {
    return includeSignerCert;
  }

  public void setIncludeSignerCert(boolean includeSignerCert) {
    this.includeSignerCert = includeSignerCert;
  }

  public boolean isSupportGetCrl() {
    return supportGetCrl;
  }

  public void setSupportGetCrl(boolean supportGetCrl) {
    this.supportGetCrl = supportGetCrl;
  }

  public long getMaxSigningTimeBias() {
    return maxSigningTimeBias;
  }

  public void setMaxSigningTimeBias(long maxSigningTimeBias) {
    this.maxSigningTimeBias = maxSigningTimeBias;
  }

}
