// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.security.util.JSON;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EstProxyConf extends ProtocolProxyConf {

  private String reverseProxyMode;

  public String getReverseProxyMode() {
    return reverseProxyMode;
  }

  public void setReverseProxyMode(String reverseProxyMode) {
    this.reverseProxyMode = reverseProxyMode;
  }

  public static EstProxyConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    EstProxyConf conf = JSON.parseObject(new File(fileName), EstProxyConf.class);
    conf.validate();
    return conf;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    TlsHelper.checkReverseProxyMode(reverseProxyMode);
  }

}
