// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class SignerConf extends ValidatableConf {

  private List<FileOrBinary> certs;

  private String type;

  private String conf;

  public List<FileOrBinary> getCerts() {
    return certs;
  }

  public void setCerts(List<FileOrBinary> certs) {
    this.certs = certs;
  }

  public String getType() {
      return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getConf() {
    return conf;
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(type, "type");
    notBlank(conf, "conf");
  }

}
