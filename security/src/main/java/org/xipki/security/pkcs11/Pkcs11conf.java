/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs11;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of PKCS#11.
 *
 * @author Lijun Liao
 */

public class Pkcs11conf extends ValidatableConf {

  public static class MechanimFilter extends ValidatableConf {

    /**
     * name of the mechanismSet.
     */
    private String mechanismSet;

    /**
     * To which slots the mechanism should be applied.
     * Absent for all slots.
     */
    private List<Slot> slots;

    public String getMechanismSet() {
      return mechanismSet;
    }

    public void setMechanismSet(String mechanismSet) {
      this.mechanismSet = mechanismSet;
    }

    public List<Slot> getSlots() {
      if (slots == null) {
        slots = new LinkedList<>();
      }
      return slots;
    }

    public void setSlots(List<Slot> slots) {
      this.slots = slots;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(mechanismSet, "mechanismSet");
      validate(slots);
    }

  } // class MechanimFilter

  public static class MechanismSet extends ValidatableConf {

    private String name;

    /**
     * The mechanism. Set mechanism to ALL to accept all available mechanisms.
     */
    private List<String> mechanisms;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public List<String> getMechanisms() {
      if (mechanisms == null) {
        mechanisms = new LinkedList<>();
      }
      return mechanisms;
    }

    public void setMechanisms(List<String> mechanisms) {
      this.mechanisms = mechanisms;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
      notEmpty(mechanisms, "mechanisms");
    }

  } // class MechanismSet

  public static class Module extends ValidatableConf {

    private String name;

    private String type;

    private List<NativeLibrary> nativeLibraries;

    private NewObjectConf newObjectConf;

    /**
     * Which slots should be considered. Absent for all slots.
     */
    private List<Slot> includeSlots;

    /**
     * Which slots should be considered. Absent for no slot.
     */
    private List<Slot> excludeSlots;

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

    private List<PasswordSet> passwordSets;

    private List<MechanimFilter> mechanismFilters;

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

    public List<NativeLibrary> getNativeLibraries() {
      if (nativeLibraries == null) {
        nativeLibraries = new LinkedList<>();
      }
      return nativeLibraries;
    }

    public void setNativeLibraries(List<NativeLibrary> nativeLibraries) {
      this.nativeLibraries = nativeLibraries;
    }

    public NewObjectConf getNewObjectConf() {
      return newObjectConf;
    }

    public void setNewObjectConf(NewObjectConf newObjectConf) {
      this.newObjectConf = newObjectConf;
    }

    public List<Slot> getIncludeSlots() {
      if (includeSlots == null) {
        includeSlots = new LinkedList<>();
      }
      return includeSlots;
    }

    public void setIncludeSlots(List<Slot> includeSlots) {
      this.includeSlots = includeSlots;
    }

    public List<Slot> getExcludeSlots() {
      if (excludeSlots == null) {
        excludeSlots = new LinkedList<>();
      }
      return excludeSlots;
    }

    public void setExcludeSlots(List<Slot> excludeSlots) {
      this.excludeSlots = excludeSlots;
    }

    public boolean isReadonly() {
      return readonly;
    }

    public void setReadonly(boolean readonly) {
      this.readonly = readonly;
    }

    public List<PasswordSet> getPasswordSets() {
      if (passwordSets == null) {
        passwordSets = new LinkedList<>();
      }
      return passwordSets;
    }

    public void setPasswordSets(List<PasswordSet> passwordSets) {
      this.passwordSets = passwordSets;
    }

    public List<MechanimFilter> getMechanismFilters() {
      if (mechanismFilters == null) {
        mechanismFilters = new LinkedList<>();
      }
      return mechanismFilters;
    }

    public void setMechanismFilters(List<MechanimFilter> mechanismFilters) {
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
      return maxMessageSize == null ? 16384 : maxMessageSize;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      notEmpty(nativeLibraries, "nativeLibraries");
      validate(nativeLibraries);
      validate(newObjectConf);
      validate(includeSlots);
      validate(excludeSlots);
      validate(passwordSets);
      notEmpty(mechanismFilters, "mechanismFilters");
      validate(mechanismFilters);
    }

  } // class Module

  public static class NativeLibrary extends ValidatableConf {

    private String path;

    private List<String> operationSystems = new LinkedList<>();

    public String getPath() {
      return path;
    }

    public void setPath(String path) {
      this.path = path;
    }

    public List<String> getOperationSystems() {
      if (operationSystems == null) {
        operationSystems = new LinkedList<>();
      }
      return operationSystems;
    }

    public void setOperationSystems(List<String> operationSystems) {
      this.operationSystems = operationSystems;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notNull(path, "path");
    }

  } // class NativeLibrary

  public static class NewObjectConf extends ValidatableConf {

    public enum CertAttribute {
      CKA_START_DATE(PKCS11Constants.CKA_START_DATE),
      CKA_END_DATE(PKCS11Constants.CKA_END_DATE),
      CKA_SUBJECT(PKCS11Constants.CKA_SUBJECT),
      CKA_ISSUER(PKCS11Constants.CKA_ISSUER),
      CKA_SERIAL_NUMBER(PKCS11Constants.CKA_SERIAL_NUMBER);

      private final long pkcs11CkaCode;

      CertAttribute(long pkcs11CkaCode) {
        this.pkcs11CkaCode = pkcs11CkaCode;
      }

      public long getPkcs11CkaCode() {
        return pkcs11CkaCode;
      }

    }

    private Boolean ignoreLabel;

    /**
     * If ID is generated randomly, specifies the number of bytes of an ID.
     */
    private Integer idLength;

    private List<CertAttribute> certAttributes = new LinkedList<>();

    public Boolean getIgnoreLabel() {
      return ignoreLabel;
    }

    public void setIgnoreLabel(Boolean ignoreLabel) {
      this.ignoreLabel = ignoreLabel;
    }

    public Integer getIdLength() {
      return idLength;
    }

    public void setIdLength(Integer idLength) {
      this.idLength = idLength;
    }

    public List<CertAttribute> getCertAttributes() {
      if (certAttributes == null) {
        certAttributes = new LinkedList<>();
      }
      return certAttributes;
    }

    public void setCertAttributes(List<CertAttribute> certAttributes) {
      this.certAttributes = certAttributes;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class NewObjectConf

  public static class PasswordSet extends ValidatableConf {

    private List<Slot> slots;

    private List<String> passwords;

    public List<Slot> getSlots() {
      if (slots == null) {
        slots = new LinkedList<>();
      }
      return slots;
    }

    public void setSlots(List<Slot> slots) {
      this.slots = slots;
    }

    public List<String> getPasswords() {
      if (passwords == null) {
        passwords = new LinkedList<>();
      }
      return passwords;
    }

    public void setPasswords(List<String> passwords) {
      this.passwords = passwords;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notEmpty(passwords, "passwords");
    }

  } // class PasswordSet

  public static class Slot extends ValidatableConf {

    private Integer index;
    /**
     * slot identifier (decimal or with the prefix 0x for heximal).
     */
    private String id;

    public Integer getIndex() {
      return index;
    }

    public void setIndex(Integer index) {
      this.index = index;
    }

    public String getId() {
      return id;
    }

    public void setId(String id) {
      this.id = id;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      exactOne(index, "index", id, "id");
    }

  } // class Slot

  /**
   * exactly one module must have the name 'default'.
   */
  private List<Module> modules;

  private List<MechanismSet> mechanismSets;

  public List<Module> getModules() {
    return modules;
  }

  public void setModules(List<Module> modules) {
    if (modules == null) {
      modules = new LinkedList<>();
    }
    this.modules = modules;
  }

  public List<MechanismSet> getMechanismSets() {
    if (mechanismSets == null) {
      mechanismSets = new LinkedList<>();
    }
    return mechanismSets;
  }

  public void setMechanismSets(List<MechanismSet> mechanismSets) {
    this.mechanismSets = mechanismSets;
  }

  public void addModule(Module module) {
    getModules().add(module);
  }

  public void addMechanismSet(MechanismSet mechanismSet) {
    getMechanismSets().add(mechanismSet);
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(modules, "modules");
    validate(modules);
    notEmpty(mechanismSets, "mechanismSets");
    validate(mechanismSets);
  }

}
