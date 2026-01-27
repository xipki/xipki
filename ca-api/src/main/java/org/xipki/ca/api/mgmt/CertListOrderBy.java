// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.misc.StringUtil;

/**
 * The mode to sort the certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public enum CertListOrderBy {

  NOT_BEFORE("notBefore"),
  NOT_BEFORE_DESC("notBefore-desc"),
  NOT_AFTER("notAfter"),
  NOT_AFTER_DESC("notAfter-desc"),
  SUBJECT("subject"),
  SUBJECT_DESC("subject-desc");

  private final String text;

  CertListOrderBy(String text) {
    this.text = text;
  }

  public String getText() {
    return text;
  }

  public static CertListOrderBy forValue(String value) {
    for (CertListOrderBy m : values()) {
      if (StringUtil.orEqualsIgnoreCase(value, m.name(), m.text)) {
        return m;
      }
    }

    return null;
  } // method forValue

}
