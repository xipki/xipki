// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

/**
 * Configuration with description.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class V1Describable {

  private final String description;

  public V1Describable(String description) {
    this.description = description;
  }

  public String getDescription() {
    return description;
  }

}
