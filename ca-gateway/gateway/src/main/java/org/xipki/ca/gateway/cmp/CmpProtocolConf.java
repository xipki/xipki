// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.ca.gateway.conf.CaNameSignersConf;
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

public class CmpProtocolConf extends ProtocolConf {

  private CmpControlConf cmp;

  private String authenticator;

  /**
   * The signers.
   */
  private CaNameSignersConf signers;

  public static CmpProtocolConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    CmpProtocolConf conf = JSON.parseConf(new File(fileName), CmpProtocolConf.class);
    conf.validate();
    return conf;
  }

  public CmpControlConf getCmp() {
    return cmp;
  }

  public void setCmp(CmpControlConf cmp) {
    this.cmp = cmp;
  }

  public String getAuthenticator() {
    return authenticator;
  }

  public void setAuthenticator(String authenticator) {
    this.authenticator = authenticator;
  }

  public CaNameSignersConf getSigners() {
    return signers;
  }

  public void setSigners(CaNameSignersConf signers) {
    this.signers = signers;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(cmp, "cmp");
    notBlank(authenticator, "authenticator");
  }

}
