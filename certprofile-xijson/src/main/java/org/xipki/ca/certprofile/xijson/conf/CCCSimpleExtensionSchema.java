// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension CCC simple ExtensionSchema.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CCCSimpleExtensionSchema extends ValidatableConf {

  private int version;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  @Override
  public void validate() throws InvalidConfException {
    if (version < 1) {
      throw new InvalidConfException("version must not be less than 1: " + version);
    }
  }

}
