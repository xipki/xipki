// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.xipki.util.codec.Args;

import java.util.Set;

/**
 * Control how to generate new keys / key-pairs.
 *
 * @author Lijun Liao (xipki)
 */
public class NewKeyControl {

  private final byte[] id;

  private final String label;

  private Boolean extractable;

  private Boolean sensitive;

  private Set<P11KeyUsage> usages;

  public byte[] id() {
    return id;
  }

  public String label() {
    return label;
  }

  public NewKeyControl(String label) {
    this(null, label);
  }

  public NewKeyControl(byte[] id, String label) {
    this.id = id;
    this.label = Args.notBlank(label, "label");
  }

  public Boolean extractable() {
    return extractable;
  }

  public void setExtractable(Boolean extractable) {
    this.extractable = extractable;
  }

  public Boolean sensitive() {
    return sensitive;
  }

  public void setSensitive(Boolean sensitive) {
    this.sensitive = sensitive;
  }

  public Set<P11KeyUsage> usages() {
    return usages;
  }

  public void setUsages(Set<P11KeyUsage> usages) {
    this.usages = usages;
  }

  public NewKeyControl copy(boolean ignoreLabel) {
    NewKeyControl ret = new NewKeyControl(id, ignoreLabel ? null : label);
    ret.extractable = extractable;
    ret.sensitive = sensitive;
    ret.usages = usages;
    return ret;
  }

  public enum P11KeyUsage {
    ENCRYPT, DECRYPT, DERIVE, SIGN, VERIFY,
    SIGN_RECOVER, VERIFY_RECOVER, WRAP, UNWRAP
  }

}
