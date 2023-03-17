// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension InhibitAnyPolicy.
 *
 * @author Lijun Liao
 */

public class InhibitAnyPolicy extends ValidatableConf {

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
