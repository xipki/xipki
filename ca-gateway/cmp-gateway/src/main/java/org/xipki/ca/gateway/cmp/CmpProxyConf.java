// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.security.util.JSON;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CmpProxyConf extends ProtocolProxyConf {

  private CmpControlConf cmp;

  public static CmpProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    CmpProxyConf conf = JSON.parseObject(new File(fileName), CmpProxyConf.class);
    conf.validate();
    return conf;
  }

  public CmpControlConf getCmp() {
    return cmp;
  }

  public void setCmp(CmpControlConf cmp) {
    this.cmp = cmp;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(cmp, "cmp");
  }

}
