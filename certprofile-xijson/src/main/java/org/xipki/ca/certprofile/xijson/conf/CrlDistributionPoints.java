// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Set;

/**
 * Extension CRLDistributionPoints.
 *
 * @author Lijun Liao
 */

public class CrlDistributionPoints extends ValidatableConf {

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
