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

package org.xipki.ca.gateway.conf;

import org.xipki.audit.Audits;
import org.xipki.security.Securities;
import org.xipki.util.exception.InvalidConfException;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public abstract class ProtocolProxyConf {

  protected boolean logReqResp;

  protected String authenticator;

  protected PopControlConf pop;

  protected SdkClientConf sdkClient;

  protected Audits.AuditConf audit;

  protected Securities.SecurityConf security;

  /**
   * The signers. If only signed with PMAC; this may be {@code null}.
   */
  protected CaNameSignersConf signers;

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public String getAuthenticator() {
    return authenticator;
  }

  public void setAuthenticator(String authenticator) {
    this.authenticator = authenticator;
  }

  public PopControlConf getPop() {
    return pop;
  }

  public void setPop(PopControlConf pop) {
    this.pop = pop;
  }

  public SdkClientConf getSdkClient() {
    return sdkClient;
  }

  public void setSdkClient(SdkClientConf sdkClient) {
    this.sdkClient = sdkClient;
  }

  public Audits.AuditConf getAudit() {
    return audit;
  }

  public void setAudit(Audits.AuditConf audit) {
    this.audit = audit;
  }

  public Securities.SecurityConf getSecurity() {
    return security;
  }

  public void setSecurity(Securities.SecurityConf security) {
    this.security = security;
  }

  public CaNameSignersConf getSigners() {
    return signers;
  }

  public void setSigners(CaNameSignersConf signers) {
    this.signers = signers;
  }

  public void validate() throws InvalidConfException {
    notNull(audit, "audit");
    notNull(authenticator, "authenticator");
    notNull(pop, "pop");
    notNull(sdkClient, "sdkClient");
    notNull(security, "security");
  }

  protected void notNull(Object obj, String name) throws InvalidConfException {
    if (obj == null) {
      throw new InvalidConfException(name + " must not be null.");
    }
  }

}
