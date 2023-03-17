// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.extn;

import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * QA extension value.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class QaExtensionValue {

  private final boolean critical;

  private final byte[] value;

  public QaExtensionValue(boolean critical, byte[] value) {
    notNull(value, "value");
    this.critical = critical;
    this.value = Arrays.copyOf(value, value.length);
  }

  public boolean isCritical() {
    return critical;
  }

  public byte[] getValue() {
    return Arrays.copyOf(value, value.length);
  }

}
