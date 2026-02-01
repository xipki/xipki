// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * CA configuration entry with database table id.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class IdentifiedDbObject implements JsonEncodable {

  private final long id;

  protected IdentifiedDbObject(long id) {
    this.id = id;
  }

  public Long id() {
    return id;
  }

  protected void toJson(JsonMap json) {
    json.put("id", id);
  }

}
