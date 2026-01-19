// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.util.codec.Args;

/**
 * Object with id.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IdentifiedObject {

  private final String id;

  public IdentifiedObject(String id) {
    this.id = Args.notBlank(id, "id");
  }

  public String getId() {
    return id;
  }

}
