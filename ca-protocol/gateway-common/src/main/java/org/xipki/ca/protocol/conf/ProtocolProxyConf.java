package org.xipki.ca.protocol.conf;

import org.xipki.audit.Audits;
import org.xipki.security.Securities;
import org.xipki.util.exception.InvalidConfException;

public abstract class ProtocolProxyConf {

  private boolean logReqResp;

  private String authenticator;

  private PopControlConf pop;

  private SdkClientConf sdkClient;

  private Audits.AuditConf audit;

  private Securities.SecurityConf security;

  /**
   * The signer. If only signed with PMAC; this may be {@code null}.
   */
  private SignerConf signer;

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


  public SignerConf getSigner() {
    return signer;
  }

  public void setSigner(SignerConf signer) {
    this.signer = signer;
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
