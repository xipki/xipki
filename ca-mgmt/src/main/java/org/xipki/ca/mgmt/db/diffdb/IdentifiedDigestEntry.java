// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.xipki.util.codec.Args;

/**
 * DigestEntry with the id and caId in database.
 *
 * @author Lijun Liao (xipki)
 */

class IdentifiedDigestEntry {

  private final DigestEntry content;

  private Integer caId;

  private final long id;

  public IdentifiedDigestEntry(DigestEntry content, long id) {
    this.content = Args.notNull(content, "content");
    this.id = id;
  }

  public long id() {
    return id;
  }

  public DigestEntry content() {
    return content;
  }

  public void setCaId(Integer caId) {
    this.caId = caId;
  }

  public Integer caId() {
    return caId;
  }

}
