// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CaNameSignerConf {

  private List<String> names;

  private SignerConf signer;

  public List<String> getNames() {
    return names;
  }

  public void setNames(List<String> names) {
    this.names = names;
  }

  public SignerConf getSigner() {
    return signer;
  }

  public void setSigner(SignerConf signer) {
    this.signer = signer;
  }
}
