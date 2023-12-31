// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.Securities.SecurityConf;
import org.xipki.util.IoUtil;
import org.xipki.util.JSON;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.nio.file.Paths;

/**
 * Configuration of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspConf extends ValidableConf {

  public static final String DFLT_SERVER_CONF = "ocsp/etc/ocsp-responder.json";

  private boolean logReqResp;

  private String serverConf;

  private SecurityConf security;

  public static OcspConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    notBlank(fileName, "fileName");
    OcspConf conf = JSON.parseConf(Paths.get(IoUtil.expandFilepath(fileName, true)), OcspConf.class);
    conf.validate();
    return conf;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public String getServerConf() {
    return serverConf == null ? DFLT_SERVER_CONF : serverConf;
  }

  public void setServerConf(String serverConf) {
    this.serverConf = serverConf;
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public void setSecurity(SecurityConf security) {
    this.security = security;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(security);
  }

}
