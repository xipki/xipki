// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.security.Securities;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.audit.Audits;

import java.io.IOException;
import java.nio.file.Path;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class GatewayConf {

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

    public static SupportedProtocols parse(JsonMap json)
        throws CodecException {
      SupportedProtocols ret = new SupportedProtocols();
      ret.setAcme(json.getBool("acme", false));
      ret.setCmp (json.getBool("cmp",  false));
      ret.setEst (json.getBool("est",  false));
      ret.setRest(json.getBool("rest", false));
      ret.setScep(json.getBool("scep", false));
      return ret;
    }
  }

  private final SupportedProtocols protocols;

  private final PopControlConf pop;

  private final SdkClientConf sdkClient;

  private final Audits.AuditConf audit;

  private final Securities.SecurityConf security;

  private boolean logReqResp;

  private String reverseProxyMode;

  public GatewayConf(SupportedProtocols protocols, PopControlConf pop,
                     SdkClientConf sdkClient, Audits.AuditConf audit,
                     Securities.SecurityConf security) {
    this.protocols = Args.notNull(protocols, "protocols");
    this.pop = Args.notNull(pop, "pop");
    this.sdkClient = Args.notNull(sdkClient, "sdkClient");
    this.audit = Args.notNull(audit, "audit");
    this.security = Args.notNull(security, "security");
  }

  public static GatewayConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try {
      JsonMap map = JsonParser.parseMap(Path.of(fileName), true);
      return GatewayConf.parse(map);
    } catch (CodecException e) {
      throw new InvalidConfException("invalid GatewayConf: " + fileName, e);
    }
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

  public SdkClientConf getSdkClient() {
    return sdkClient;
  }

  public Audits.AuditConf getAudit() {
    return audit;
  }

  public Securities.SecurityConf getSecurity() {
    return security;
  }

  public SupportedProtocols getProtocols() {
    return protocols;
  }

  public static GatewayConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("protocols");
    SupportedProtocols protocols = (map == null) ? null
        : SupportedProtocols.parse(map);

    map = json.getMap("pop");
    PopControlConf pop = (map == null) ? null : PopControlConf.parse(map);

    map = json.getMap("sdkClient");
    SdkClientConf sdkClient = (map == null) ? null : SdkClientConf.parse(map);

    map = json.getMap("audit");
    Audits.AuditConf audit = (map == null) ? null : Audits.AuditConf.parse(map);

    map = json.getMap("security");
    Securities.SecurityConf security = (map == null) ? null
        : Securities.SecurityConf.parse(map);

    GatewayConf ret = new GatewayConf(protocols, pop, sdkClient,
        audit, security);
    Boolean b = json.getBool("logReqResp");
    if (b != null) {
      ret.setLogReqResp(b);
    }

    String str = json.getString("reverseProxyMode");
    if (str != null) {
      ret.setReverseProxyMode(str);
    }

    return ret;
  }

}
