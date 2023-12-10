// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import java.util.List;

/**
 * POP (proof-of-possession) control configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class PopControlConf {

  private List<String> sigAlgos;

  private KeystoreConf dh;

  public List<String> getSigAlgos() {
    return sigAlgos;
  }

  public void setSigAlgos(List<String> sigAlgos) {
    this.sigAlgos = sigAlgos;
  }

  public KeystoreConf getDh() {
    return dh;
  }

  public void setDh(KeystoreConf dh) {
    this.dh = dh;
  }
}
