// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension InhibitAnyPolicy.
 *
 * @author Lijun Liao (xipki)
 */

public class InhibitAnyPolicy extends ValidableConf {

  private int skipCerts;

  public int getSkipCerts() {
    return skipCerts;
  }

  public void setSkipCerts(int skipCerts) {
    this.skipCerts = skipCerts;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class InhibitAnyPolicy
