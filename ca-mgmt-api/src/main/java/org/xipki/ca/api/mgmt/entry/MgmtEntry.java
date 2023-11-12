// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * CA management entry.
 *
 * @author Lijun Liao (xipki)
 *
 */
public abstract class MgmtEntry extends ValidatableConf {

  @Override
  public void validate() throws InvalidConfException {
  }

}
