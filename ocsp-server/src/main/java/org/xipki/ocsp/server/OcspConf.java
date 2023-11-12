// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.Securities.SecurityConf;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.FileOrBinary;
import org.xipki.util.IoUtil;
import org.xipki.util.JSON;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;

/**
 * Configuration of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspConf extends ValidableConf {

  public static class RemoteMgmt extends ValidableConf {

    private boolean enabled;

    private List<FileOrBinary> certs;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public List<FileOrBinary> getCerts() {
      return certs;
    }

    public void setCerts(List<FileOrBinary> certs) {
      this.certs = certs;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class RemoteMgmt

  public static final String DFLT_SERVER_CONF = "ocsp/etc/ocsp-responder.json";

  private boolean logReqResp;

  private String reverseProxyMode;

  private String serverConf;

  private RemoteMgmt remoteMgmt;

  private SecurityConf security;

  public static OcspConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    notBlank(fileName, "fileName");
    OcspConf conf = JSON.parseObject(Paths.get(IoUtil.expandFilepath(fileName, true)), OcspConf.class);
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

  public String getServerConf() {
    return serverConf == null ? DFLT_SERVER_CONF : serverConf;
  }

  public void setServerConf(String serverConf) {
    this.serverConf = serverConf;
  }

  public RemoteMgmt getRemoteMgmt() {
    return remoteMgmt;
  }

  public void setRemoteMgmt(RemoteMgmt remoteMgmt) {
    this.remoteMgmt = remoteMgmt;
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public void setSecurity(SecurityConf security) {
    this.security = security;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(remoteMgmt, security);
    TlsHelper.checkReverseProxyMode(reverseProxyMode);
  }

}
