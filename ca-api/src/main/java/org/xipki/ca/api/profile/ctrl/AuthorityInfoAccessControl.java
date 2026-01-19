// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

/**
 * @author Lijun Liao (xipki)
 */
public class AuthorityInfoAccessControl {

  private final boolean includesCaIssuers;

  private final boolean includesOcsp;

  public AuthorityInfoAccessControl(
      boolean includesCaIssuers, boolean includesOcsp) {
    this.includesCaIssuers = includesCaIssuers;
    this.includesOcsp = includesOcsp;
  }

  public boolean isIncludesCaIssuers() {
    return includesCaIssuers;
  }

  public boolean isIncludesOcsp() {
    return includesOcsp;
  }

} // class AuthorityInfoAccessControl
