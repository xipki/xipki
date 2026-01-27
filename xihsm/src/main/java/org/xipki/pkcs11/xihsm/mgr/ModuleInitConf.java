// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class ModuleInitConf {

  private final List<Slot> slots;

  public ModuleInitConf(List<Slot> slots) {
    this.slots = slots;
  }

  public List<Slot> getSlots() {
    return slots;
  }

  public static final class Slot {
    private final long id;
    private final String soPin;
    private final String userPin;

    public Slot(long id, String soPin, String userPin) {
      this.id = id;
      this.soPin = soPin;
      this.userPin = userPin;
    }

    public long getId() {
      return id;
    }

    public String getSoPin() {
      return soPin;
    }

    public String getUserPin() {
      return userPin;
    }
  }

}
