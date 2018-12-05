/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class MechanimFilterType extends ValidatableConf {

  /**
   * name of the mechanismSet.
   */
  private String mechanismSet;

  /**
   * To which slots the mechanism should be applied.
   * Absent for all slots.
   */
  private List<SlotType> slots;

  public String getMechanismSet() {
    return mechanismSet;
  }

  public void setMechanismSet(String mechanismSet) {
    this.mechanismSet = mechanismSet;
  }

  public List<SlotType> getSlots() {
    if (slots == null) {
      slots = new LinkedList<>();
    }
    return slots;
  }

  public void setSlots(List<SlotType> slots) {
    this.slots = slots;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(mechanismSet, "mechanismSet");
    validate(slots);
  }

}
