// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
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

public class ScepProxyConf extends ProtocolProxyConf {

  private ScepControl scep;

  public static ScepProxyConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    ScepProxyConf conf = JSON.parseObject(new File(fileName), ScepProxyConf.class);
    conf.validate();
    return conf;
  }

  public ScepControl getScep() {
    return scep;
  }

  public void setScep(ScepControl scep) {
    this.scep = scep;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(signers, "signers");
    notNull(scep, "scep");
  }
}
