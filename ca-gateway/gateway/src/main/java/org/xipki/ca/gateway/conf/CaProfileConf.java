// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.ca.gateway.conf;

import org.xipki.util.exception.InvalidConfException;

import java.util.Locale;

/**
 * Gateway's CA-Profile Map.
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class CaProfileConf {

  private String name;

  private String ca;

  private String certprofile;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name == null ? null : name.toLowerCase(Locale.ROOT);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public void validate() throws InvalidConfException {
    if (name == null || name.isEmpty()) {
      throw new InvalidConfException("name must be present and not blank.");
    }

    if (ca == null || ca.isEmpty()) {
      throw new InvalidConfException("ca must be present and not blank.");
    }

    if (certprofile == null || certprofile.isEmpty()) {
      throw new InvalidConfException("profile must be present and not blank.");
    }
  }

}
