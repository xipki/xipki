// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.util.Args;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Configuration of PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */

public class Pkcs11conf extends ValidableConf {

  public static class MechanismFilter extends ValidableConf {

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
    public void validate() throws InvalidConfException {
      notBlank(mechanismSet, "mechanismSet");
      validate(slots);
    }

  } // class MechanismFilter

  public static class MechanismSet extends ValidableConf {

    private String name;

    /**
     * The mechanism. Set mechanism to ALL to accept all available mechanisms.
     */
    private List<String> mechanisms;

    /**
     * The mechanism to be excluded.
     */
    private List<String> excludeMechanisms;

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

    public List<String> getExcludeMechanisms() {
      if (excludeMechanisms == null) {
        excludeMechanisms = new LinkedList<>();
      }
      return excludeMechanisms;
    }

    public void setExcludeMechanisms(List<String> excludeMechanisms) {
      this.excludeMechanisms = excludeMechanisms;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notEmpty(mechanisms, "mechanisms");
    }

  } // class MechanismSet

  public static class Module extends ValidableConf {

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

    private List<String> secretKeyTypes;

    private List<String> keyPairTypes;

    private Integer numSessions;

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

    private String userName;

    /**
     * maximal size of the message sent to the PKCS#11 device.
     */
    private Integer maxMessageSize;

    /**
     * Timeout to borrow a new session.
     */
    private Integer newSessionTimeout;

    private List<PasswordSet> passwordSets;

    private List<MechanismFilter> mechanismFilters;

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

    public List<MechanismFilter> getMechanismFilters() {
      if (mechanismFilters == null) {
        mechanismFilters = new LinkedList<>();
      }
      return mechanismFilters;
    }

    public void setMechanismFilters(List<MechanismFilter> mechanismFilters) {
      this.mechanismFilters = mechanismFilters;
    }

    public void setUser(String user) {
      this.user = user;
    }

    public void setUserName(String userName) {
      this.userName = userName;
    }

    public void setMaxMessageSize(Integer maxMessageSize) {
      this.maxMessageSize = maxMessageSize;
    }

    public String getUser() {
      return user == null ? "CKU_USER" : user;
    }

    public String getUserName() {
      return userName;
    }

    public int getMaxMessageSize() {
      return maxMessageSize == null ? 16384 : maxMessageSize;
    }

    public List<String> getSecretKeyTypes() {
      return secretKeyTypes;
    }

    public void setSecretKeyTypes(List<String> secretKeyTypes) {
      this.secretKeyTypes = secretKeyTypes;
    }

    public List<String> getKeyPairTypes() {
      return keyPairTypes;
    }

    public void setKeyPairTypes(List<String> keyPairTypes) {
      this.keyPairTypes = keyPairTypes;
    }

    public Integer getNumSessions() {
      return numSessions;
    }

    public void setNumSessions(Integer numSessions) {
      this.numSessions = numSessions;
    }

    public Integer getNewSessionTimeout() {
      return newSessionTimeout;
    }

    public void setNewSessionTimeout(Integer newSessionTimeout) {
      this.newSessionTimeout = newSessionTimeout;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      notEmpty(nativeLibraries, "nativeLibraries");

      validate(nativeLibraries, includeSlots, excludeSlots, passwordSets, mechanismFilters);
    }

  } // class Module

  public static class NativeLibrary extends ValidableConf {

    private String path;

    private Map<String, String> properties;

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

    public Map<String, String> getProperties() {
      return properties;
    }

    public void setProperties(Map<String, String> properties) {
      this.properties = properties;
    }

    @Override
    public void validate() throws InvalidConfException {
      Args.notNull(path, "path");
    }

  } // class NativeLibrary

  public static class NewObjectConf extends ValidableConf {

    private Boolean ignoreLabel;

    /**
     * If ID is generated randomly, specifies the number of bytes of an ID.
     */
    private Integer idLength;

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

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class NewObjectConf

  public static class PasswordSet extends ValidableConf {

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
    public void validate() throws InvalidConfException {
      notEmpty(passwords, "passwords");
    }

  } // class PasswordSet

  public static class Slot extends ValidableConf {

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
    public void validate() throws InvalidConfException {
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
  public void validate() throws InvalidConfException {
    notEmpty(modules, "modules");
    validate(modules, mechanismSets);
  }

}
