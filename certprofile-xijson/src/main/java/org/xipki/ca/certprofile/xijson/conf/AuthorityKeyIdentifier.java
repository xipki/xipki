// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension AuthorityKeyIdentifier.
 *
 * @author Lijun Liao (xipki)
 */

public class AuthorityKeyIdentifier extends ValidatableConf {

  private boolean useIssuerAndSerial;

  public boolean isUseIssuerAndSerial() {
    return useIssuerAndSerial;
  }

  public void setUseIssuerAndSerial(boolean useIssuerAndSerial) {
    this.useIssuerAndSerial = useIssuerAndSerial;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class AuthorityKeyIdentifier
