// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class SubjectInfo {

  private final X500Name grantedSubject;

  private final String warning;

  public SubjectInfo(X500Name grantedSubject, String warning) {
    this.grantedSubject = Args.notNull(grantedSubject, "grantedSubject");
    this.warning = warning;
  }

  public X500Name getGrantedSubject() {
    return grantedSubject;
  }

  public String getWarning() {
    return warning;
  }

}
