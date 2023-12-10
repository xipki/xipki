// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.ca.gateway.conf.*;
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

public class ScepProtocolConf extends ProtocolConf {

  private ScepControl scep;

  private String authenticator;

  private CaProfileConf[] caProfiles;

  /**
   * The signers.
   */
  private CaNameSignersConf signers;

  public static ScepProtocolConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    ScepProtocolConf conf = JSON.parseConf(new File(fileName), ScepProtocolConf.class);
    conf.validate();
    return conf;
  }

  public ScepControl getScep() {
    return scep;
  }

  public void setScep(ScepControl scep) {
    this.scep = scep;
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

  public CaNameSignersConf getSigners() {
    return signers;
  }

  public void setSigners(CaNameSignersConf signers) {
    this.signers = signers;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(authenticator, "authenticator");
    if (caProfiles != null) {
      new CaProfilesControl(caProfiles).validate();
    }
    notNull(signers, "signers");
    notNull(scep, "scep");
  }
}
