// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.security.util.TlsHelper;
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

public class RestProxyConf extends ProtocolProxyConf {

  private String reverseProxyMode;

  public static RestProxyConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    RestProxyConf conf = JSON.parseObject(new File(fileName), RestProxyConf.class);
    conf.validate();
    return conf;
  }

  public String getReverseProxyMode() {
    return reverseProxyMode;
  }

  public void setReverseProxyMode(String reverseProxyMode) {
    this.reverseProxyMode = reverseProxyMode;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    TlsHelper.checkReverseProxyMode(reverseProxyMode);
  }

}
