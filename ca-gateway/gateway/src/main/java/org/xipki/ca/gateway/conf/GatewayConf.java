// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.audit.Audits;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.security.Securities;
import org.xipki.util.Args;
import org.xipki.util.JSON;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class GatewayConf extends ValidableConf {

  public static class SupportedProtocols {

    private boolean acme;

    private boolean cmp;

    private boolean est;

    private boolean rest;

    private boolean scep;

    public boolean isAcme() {
      return acme;
    }

    public void setAcme(boolean acme) {
      this.acme = acme;
    }

    public boolean isCmp() {
      return cmp;
    }

    public void setCmp(boolean cmp) {
      this.cmp = cmp;
    }

    public boolean isEst() {
      return est;
    }

    public void setEst(boolean est) {
      this.est = est;
    }

    public boolean isRest() {
      return rest;
    }

    public void setRest(boolean rest) {
      this.rest = rest;
    }

    public boolean isScep() {
      return scep;
    }

    public void setScep(boolean scep) {
      this.scep = scep;
    }
  }

  private SupportedProtocols protocols;

  private boolean logReqResp;

  private String reverseProxyMode;

  private PopControlConf pop;

  private SdkClientConf sdkClient;

  private Audits.AuditConf audit;

  private Securities.SecurityConf security;

  public static GatewayConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    GatewayConf conf = JSON.parseConf(new File(fileName), GatewayConf.class);
    conf.validate();
    return conf;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public String getReverseProxyMode() {
    return reverseProxyMode;
  }

  public void setReverseProxyMode(String reverseProxyMode) {
    this.reverseProxyMode = reverseProxyMode;
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

  public SupportedProtocols getProtocols() {
    return protocols;
  }

  public void setProtocols(SupportedProtocols protocols) {
    this.protocols = protocols;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(protocols, "protocols");
    notNull(audit, "audit");
    notNull(pop, "pop");
    notNull(sdkClient, "sdkClient");
    notNull(security, "security");
  }

}
