// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * CA configuration entry with database table id.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class IdentifiedDbObject extends ValidatableConf {

  private Long id;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(id, "id");
  }

}
