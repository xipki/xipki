/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.cmpclient.conf;

import org.xipki.cmpclient.conf.CertprofileType.Certprofiles;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CaType extends ValidatableConf {

  public static class CaCertType extends ValidatableConf {

    private boolean autoconf;

    private FileOrBinary cert;

    public boolean isAutoconf() {
      return autoconf;
    }

    public void setAutoconf(boolean autoconf) {
      this.autoconf = autoconf;
    }

    public FileOrBinary getCert() {
      return autoconf ? null : cert;
    }

    public void setCert(FileOrBinary value) {
      this.cert = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (!autoconf) {
        notNull(cert, "cert");
        validate(cert);
      }
    }

  }

  private String name;

  private String url;

  private String healthUrl;

  private String ssl;

  private String requestor;

  private String responder;

  private CmpcontrolType cmpcontrol;

  private CaCertType caCert;

  private CertprofileType.Certprofiles certprofiles;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getHealthUrl() {
    return healthUrl;
  }

  public void setHealthUrl(String healthUrl) {
    this.healthUrl = healthUrl;
  }

  public String getSsl() {
    return ssl;
  }

  public void setSsl(String ssl) {
    this.ssl = ssl;
  }

  public String getRequestor() {
    return requestor;
  }

  public void setRequestor(String requestor) {
    this.requestor = requestor;
  }

  public String getResponder() {
    return responder;
  }

  public void setResponder(String responder) {
    this.responder = responder;
  }

  public CmpcontrolType getCmpcontrol() {
    return cmpcontrol;
  }

  public void setCmpcontrol(CmpcontrolType cmpcontrol) {
    this.cmpcontrol = cmpcontrol;
  }

  public CaCertType getCaCert() {
    return caCert;
  }

  public void setCaCert(CaCertType caCert) {
    this.caCert = caCert;
  }

  public Certprofiles getCertprofiles() {
    return certprofiles;
  }

  public void setCertprofiles(Certprofiles certprofiles) {
    this.certprofiles = certprofiles;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notEmpty(url, "url");
    notEmpty(requestor, "requestor");
    notEmpty(responder, "responder");
    notNull(cmpcontrol, "cmpcontrol");
    validate(cmpcontrol);
    notNull(caCert, "caCert");
    validate(caCert);
    notNull(certprofiles, "certprofiles");
    validate(certprofiles);
  }

}
