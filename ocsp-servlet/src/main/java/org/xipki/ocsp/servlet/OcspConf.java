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

package org.xipki.ocsp.servlet;

import com.alibaba.fastjson.JSON;
import org.xipki.security.Securities.SecurityConf;
import org.xipki.util.FileOrBinary;
import org.xipki.util.IoUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * Configuration of the OCSP server.
 *
 * @author Lijun Liao
 */
public class OcspConf extends ValidatableConf {

  public static class RemoteMgmt extends ValidatableConf {

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
    public void validate()
        throws InvalidConfException {
    }

  } // class RemoteMgmt

  public static final String DFLT_SERVER_CONF = "ocsp/etc/ocsp-responder.json";

  private boolean logReqResp;

  private String serverConf;

  private RemoteMgmt remoteMgmt;

  private SecurityConf security;

  public static OcspConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(
                            Paths.get(IoUtil.expandFilepath(fileName, true)))) {
      OcspConf conf = JSON.parseObject(is, OcspConf.class);
      conf.validate();

      return conf;
    }
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
  public void validate()
      throws InvalidConfException {
    validate(remoteMgmt);
    validate(security);
  }

}
