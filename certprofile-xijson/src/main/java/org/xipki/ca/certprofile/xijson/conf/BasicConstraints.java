// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension BasicConstraints.
 *
 * @author Lijun Liao
 */

public class BasicConstraints extends ValidatableConf {

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
