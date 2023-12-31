// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension BasicConstraints.
 *
 * @author Lijun Liao (xipki)
 */

public class BasicConstraints extends ValidableConf {

  private int pathLen;

  public int getPathLen() {
    return pathLen;
  }

  public void setPathLen(int pathLen) {
    this.pathLen = pathLen;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class BasicConstraints
