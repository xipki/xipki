// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest;

import org.xipki.ca.gateway.conf.CaProfileConf;
import org.xipki.ca.gateway.conf.CaProfilesControl;
import org.xipki.ca.gateway.conf.ProtocolConf;
import org.xipki.util.Args;
import org.xipki.util.JSON;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class RestProtocolConf extends ProtocolConf {

  private String authenticator;

  private CaProfileConf[] caProfiles;

  public static RestProtocolConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    RestProtocolConf conf = JSON.parseConf(new File(fileName), RestProtocolConf.class);
    conf.validate();
    return conf;
  }

  public String getAuthenticator() {
    return authenticator;
  }

  public void setAuthenticator(String authenticator) {
    this.authenticator = authenticator;
  }

  public CaProfileConf[] getCaProfiles() {
    return caProfiles;
  }

  public void setCaProfiles(CaProfileConf[] caProfiles) {
    this.caProfiles = caProfiles;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(authenticator, "authenticator");
    if (caProfiles != null) {
      new CaProfilesControl(caProfiles).validate();
    }
  }

}
