// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Set;

/**
 * Extension CRLDistributionPoints.
 *
 * @author Lijun Liao (xipki)
 */

public class CrlDistributionPoints extends ValidableConf {

  private Set<String> protocols;

  public Set<String> getProtocols() {
    return protocols;
  }

  public void setProtocols(Set<String> protocols) {
    this.protocols = protocols;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class CrlDistributionPoints
