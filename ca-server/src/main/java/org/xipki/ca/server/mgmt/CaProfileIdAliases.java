// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

/**
 * CA_HAS_PROFILE profile id and aliases.
 * @author Lijun Liao (xipki)
 */

public class CaProfileIdAliases {

  private final int id;

  private final String aliases;

  public CaProfileIdAliases(int id, String aliases) {
    this.id = id;
    this.aliases = aliases;
  }

  public int getId() {
    return id;
  }

  public String getAliases() {
    return aliases;
  }
}
