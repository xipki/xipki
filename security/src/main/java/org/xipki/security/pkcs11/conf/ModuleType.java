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

public class ModuleType extends ValidatableConf {

  private String name;

  private String type;

  private List<NativeLibraryType> nativeLibraries;

  private NewObjectConfType newObjectConf;

  /**
   * Which slots should be considered. Absent for all slots.
   */
  private List<SlotType> includeSlots;

  /**
   * Which slots should be considered. Absent for no slot.
   */
  private List<SlotType> excludeSlots;

  private boolean readonly;

  /**
   * specify the user type, use either the long value or identifier as
   * defined in the PKCS#11 standards. In version up to 2.40 the
   * following users are defined.
   *   - 0 or 0x0 or CKU_SO
   *   - 1 or 0x1 or CKU_USER
   *   - 2 or 0x2 or CKU_CONTEXT_SPECIFIC
   * For vendor user type, only the long value is allowed.
   */
  private String user;

  /**
   * maximal size of the message sent to the PKCS#11 device.
   */
  private Integer maxMessageSize;

  private List<PasswordSetType> passwordSets;

  private List<MechanimFilterType> mechanismFilters;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public List<NativeLibraryType> getNativeLibraries() {
    if (nativeLibraries == null) {
      nativeLibraries = new LinkedList<>();
    }
    return nativeLibraries;
  }

  public void setNativeLibraries(List<NativeLibraryType> nativeLibraries) {
    this.nativeLibraries = nativeLibraries;
  }

  public NewObjectConfType getNewObjectConf() {
    return newObjectConf;
  }

  public void setNewObjectConf(NewObjectConfType newObjectConf) {
    this.newObjectConf = newObjectConf;
  }

  public List<SlotType> getIncludeSlots() {
    if (includeSlots == null) {
      includeSlots = new LinkedList<>();
    }
    return includeSlots;
  }

  public void setIncludeSlots(List<SlotType> includeSlots) {
    this.includeSlots = includeSlots;
  }

  public List<SlotType> getExcludeSlots() {
    if (excludeSlots == null) {
      excludeSlots = new LinkedList<>();
    }
    return excludeSlots;
  }

  public void setExcludeSlots(List<SlotType> excludeSlots) {
    this.excludeSlots = excludeSlots;
  }

  public boolean isReadonly() {
    return readonly;
  }

  public void setReadonly(boolean readonly) {
    this.readonly = readonly;
  }

  public List<PasswordSetType> getPasswordSets() {
    if (passwordSets == null) {
      passwordSets = new LinkedList<>();
    }
    return passwordSets;
  }

  public void setPasswordSets(List<PasswordSetType> passwordSets) {
    this.passwordSets = passwordSets;
  }

  public List<MechanimFilterType> getMechanismFilters() {
    if (mechanismFilters == null) {
      mechanismFilters = new LinkedList<>();
    }
    return mechanismFilters;
  }

  public void setMechanismFilters(List<MechanimFilterType> mechanismFilters) {
    this.mechanismFilters = mechanismFilters;
  }

  public void setUser(String user) {
    this.user = user;
  }

  public void setMaxMessageSize(Integer maxMessageSize) {
    this.maxMessageSize = maxMessageSize;
  }

  public String getUser() {
    return user == null ? "CKU_USER" : user;
  }

  public int getMaxMessageSize() {
    return maxMessageSize == null ? 16384 : maxMessageSize.intValue();
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notEmpty(type, "type");
    notEmpty(nativeLibraries, "nativeLibraries");
    validate(nativeLibraries);
    validate(newObjectConf);
    validate(includeSlots);
    validate(excludeSlots);
    notEmpty(passwordSets, "passwordSets");
    validate(passwordSets);
    notEmpty(mechanismFilters, "mechanismFilters");
    validate(mechanismFilters);
  }

}
