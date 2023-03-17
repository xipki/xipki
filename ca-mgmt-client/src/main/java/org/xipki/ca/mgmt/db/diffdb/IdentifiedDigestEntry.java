// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.xipki.util.Args;

/**
 * DigestEntry with the id and caId in database.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class IdentifiedDigestEntry {

  private final DigestEntry content;

  private Integer caId;

  private final long id;

  public IdentifiedDigestEntry(DigestEntry content, long id) {
    this.content = Args.notNull(content, "content");
    this.id = id;
  }

  public long getId() {
    return id;
  }

  public DigestEntry getContent() {
    return content;
  }

  public void setCaId(Integer caId) {
    this.caId = caId;
  }

  public Integer getCaId() {
    return caId;
  }

}
