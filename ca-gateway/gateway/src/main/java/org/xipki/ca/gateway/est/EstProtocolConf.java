// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est;

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

public class EstProtocolConf extends ProtocolConf {

  private String authenticator;

  private CaProfileConf[] caProfiles;

  public static EstProtocolConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    EstProtocolConf conf = JSON.parseConf(new File(fileName), EstProtocolConf.class);
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
