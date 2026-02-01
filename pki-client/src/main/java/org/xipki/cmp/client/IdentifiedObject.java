// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.util.codec.Args;

/**
 * Object with id.
 *
 * @author Lijun Liao (xipki)
 */

public class IdentifiedObject {

  private final String id;

  public IdentifiedObject(String id) {
    this.id = Args.notBlank(id, "id");
  }

  public String id() {
    return id;
  }

}
