// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.util.codec.Args;

import java.util.Set;

/**
 * Control how to generate new keys / key-pairs.
 *
 * @author Lijun Liao (xipki)
 */
class NewKeyControl {

  enum P11KeyUsage {
    ENCRYPT, DECRYPT, DERIVE, SIGN, VERIFY, SIGN_RECOVER, VERIFY_RECOVER, WRAP, UNWRAP,
    ENCAPSULATE, DECAPSULATE
  }

  private final byte[] id;
  private final String label;
  private Boolean extractable;
  private Boolean sensitive;
  private Set<P11KeyUsage> usages;

  NewKeyControl(byte[] id, String label) {
    this.id = id;
    this.label = Args.notBlank(label, "label");
  }

  byte[] id() {
    return id;
  }

  String label() {
    return label;
  }

  Boolean extractable() {
    return extractable;
  }

  void setExtractable(Boolean extractable) {
    this.extractable = extractable;
  }

  Boolean sensitive() {
    return sensitive;
  }

  void setSensitive(Boolean sensitive) {
    this.sensitive = sensitive;
  }

  Set<P11KeyUsage> usages() {
    return usages;
  }

  void setUsages(Set<P11KeyUsage> usages) {
    this.usages = usages;
  }
}
