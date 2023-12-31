// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * CA management entry.
 *
 * @author Lijun Liao (xipki)
 *
 */
public abstract class MgmtEntry extends ValidableConf {

  @Override
  public void validate() throws InvalidConfException {
  }

}
