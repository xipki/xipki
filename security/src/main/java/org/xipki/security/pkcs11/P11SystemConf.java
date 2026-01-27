// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.io.FileOrValue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Configuration of PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */

public class P11SystemConf {

  public static class MechanismFilterConf {

    /**
     * name of the mechanismSet.
     */
    private final String mechanismSet;

    /**
     * To which slots the mechanism should be applied.
     * Absent for all slots.
     */
    private final List<SlotConf> slots;

    public MechanismFilterConf(String mechanismSet, List<SlotConf> slots) {
      this.mechanismSet = Args.notBlank(mechanismSet, "mechanismSet");
      this.slots = (slots == null) ? new LinkedList<>() : slots;
    }

    public String getMechanismSet() {
      return mechanismSet;
    }

    public List<SlotConf> getSlots() {
      return slots;
    }

    public static MechanismFilterConf parse(JsonMap json)
        throws CodecException {
      List<SlotConf> slots = null;
      JsonList list = json.getList("slots");
      if (list != null) {
        slots = SlotConf.parseList(list);
      }

      return new MechanismFilterConf(json.getString("mechanismSet"), slots);
    }

    public static List<MechanismFilterConf> parseList(JsonList json)
        throws CodecException {
      List<MechanismFilterConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  } // class MechanismFilter

  public static class MechanismSetConf {

    private final String name;

    /**
     * The mechanism. Set mechanism to ALL to accept all available mechanisms.
     */
    private final List<String> mechanisms;

    /**
     * The mechanism to be excluded.
     */
    private final List<String> excludeMechanisms;

    public MechanismSetConf(String name, List<String> mechanisms,
                            List<String> excludeMechanisms) {
      this.name = Args.notBlank(name, "name");
      this.mechanisms = Args.notEmpty(mechanisms, "mechanisms");
      this.excludeMechanisms = (excludeMechanisms == null) ? new LinkedList<>()
          : excludeMechanisms;
    }

    public String getName() {
      return name;
    }

    public List<String> getMechanisms() {
      return mechanisms;
    }

    public List<String> getExcludeMechanisms() {
      return excludeMechanisms;
    }

    public static MechanismSetConf parse(JsonMap json) throws CodecException {
      return new MechanismSetConf(json.getNnString("name"),
          json.getNnStringList("mechanisms"),
          json.getStringList("excludeMechanisms"));
    }

  } // class MechanismSet

  public static class ModuleConf {

    private final String name;

    private final List<NativeLibraryConf> nativeLibraries;

    /**
     * Which slots should be considered. Absent for all slots.
     */
    private List<SlotConf> includeSlots;

    /**
     * Which slots should be considered. Absent for no slot.
     */
    private List<SlotConf> excludeSlots;

    private boolean readonly;

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

    private List<PasswordSetConf> passwordSets;

    private List<MechanismFilterConf> mechanismFilters;

    public ModuleConf(String name, List<NativeLibraryConf> nativeLibraries) {
      this.name = Args.notBlank(name, "name");
      this.nativeLibraries = Args.notEmpty(nativeLibraries, "nativeLibraries");
    }

    public String getName() {
      return name;
    }

    public List<NativeLibraryConf> getNativeLibraries() {
      return nativeLibraries;
    }

    public List<SlotConf> getIncludeSlots() {
      return includeSlots;
    }

    public void setIncludeSlots(List<SlotConf> includeSlots) {
      this.includeSlots = includeSlots;
    }

    public List<SlotConf> getExcludeSlots() {
      return excludeSlots;
    }

    public void setExcludeSlots(List<SlotConf> excludeSlots) {
      this.excludeSlots = excludeSlots;
    }

    public boolean isReadonly() {
      return readonly;
    }

    public void setReadonly(boolean readonly) {
      this.readonly = readonly;
    }

    public List<PasswordSetConf> getPasswordSets() {
      return passwordSets;
    }

    public void setPasswordSets(List<PasswordSetConf> passwordSets) {
      this.passwordSets = passwordSets;
    }

    public List<MechanismFilterConf> getMechanismFilters() {
        return mechanismFilters;
    }

    public void setMechanismFilters(
        List<MechanismFilterConf> mechanismFilters) {
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

    public static ModuleConf parse(JsonMap json) throws CodecException {
      List<NativeLibraryConf> nativeLibraries = NativeLibraryConf.parseList(
          json.getNnList("nativeLibraries"));

      ModuleConf module = new ModuleConf(json.getString("name"),
          nativeLibraries);
      module.setMaxMessageSize(json.getInt("maxMessageSize"));
      module.setNewSessionTimeout(json.getInt("newSessionTimeout"));
      module.setNumSessions(json.getInt("numSessions"));
      module.setReadonly(json.getBool("readOnly", false));
      module.setUser(json.getString("user"));
      module.setUserName(json.getString("userName"));

      JsonList list = json.getList("excludeSlots");
      if (list != null) {
        module.setExcludeSlots(SlotConf.parseList(list));
      }

      list = json.getList("includeSlots");
      if (list != null) {
        module.setIncludeSlots(SlotConf.parseList(list));
      }

      list = json.getList("mechanismFilters");
      if (list != null) {
        module.setMechanismFilters(MechanismFilterConf.parseList(list));
      }

      list = json.getList("passwordSets");
      if (list != null) {
        module.setPasswordSets(PasswordSetConf.parseList(list));
      }

      return module;
    }

  } // class Module

  public static class NativeLibraryConf {

    private final String path;

    private Map<String, String> properties;

    private List<String> operationSystems = new LinkedList<>();

    public NativeLibraryConf(String path) {
      this.path = Args.notBlank(path, "path");
    }

    public String getPath() {
      return path;
    }

    public List<String> getOperationSystems() {
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

    public static NativeLibraryConf parse(JsonMap json) throws CodecException {
      NativeLibraryConf ret = new NativeLibraryConf(json.getNnString("path"));
      ret.setProperties(json.getStringMap("properties"));
      ret.setOperationSystems(json.getStringList("operationSystems"));
      return ret;
    }

    public static List<NativeLibraryConf> parseList(JsonList json)
        throws CodecException {
      List<NativeLibraryConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }
  } // class NativeLibrary

  public static class PasswordSetConf {

    private final List<SlotConf> slots;

    private final List<String> passwords;

    public PasswordSetConf(List<SlotConf> slots, List<String> passwords) {
      this.slots = (slots == null) ? new LinkedList<>() : slots;
      this.passwords = Args.notEmpty(passwords, "passwords");
    }

    public List<SlotConf> getSlots() {
      return slots;
    }

    public List<String> getPasswords() {
      return passwords;
    }

    public static PasswordSetConf parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("slots");
      List<SlotConf> slots = (list == null) ? null : SlotConf.parseList(list);
      return new PasswordSetConf(slots, json.getNnStringList("passwords"));
    }

    public static List<PasswordSetConf> parseList(JsonList json)
        throws CodecException {
      List<PasswordSetConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  } // class PasswordSet

  public static class SlotConf {

    private final Integer index;
    /**
     * slot identifier (decimal or with the prefix 0x for heximal).
     */
    private final String id;

    public SlotConf(Integer index) {
      this.index = index;
      this.id = null;
    }

    public SlotConf(String id) {
      this.index = null;
      this.id = id;
    }

    public Integer getIndex() {
      return index;
    }

    public String getId() {
      return id;
    }

    public static SlotConf parse(JsonMap json) throws CodecException {
      String id = json.getString("id");
      Integer index = json.getInt("index");
      Args.exactOne(id, "id", index, "index");
      return (id != null) ? new SlotConf(id) : new SlotConf(index);
    }

    public static List<SlotConf> parseList(JsonList json)
        throws CodecException {
      List<SlotConf> slots = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        slots.add(SlotConf.parse(m));
      }
      return slots;
    }

  } // class Slot

  /**
   * exactly one module must have the name 'default'.
   */
  private final List<ModuleConf> modules;

  private final List<MechanismSetConf> mechanismSets;

  public P11SystemConf(List<ModuleConf> modules,
                       List<MechanismSetConf> mechanismSets) {
    this.modules = Args.notEmpty(modules, "modules");
    this.mechanismSets = (mechanismSets == null) ? new LinkedList<>()
        : mechanismSets;
  }

  public List<ModuleConf> getModules() {
    return modules;
  }

  public List<MechanismSetConf> getMechanismSets() {
    return mechanismSets;
  }

  public static P11SystemConf parse(FileOrValue fileOrValue)
      throws InvalidConfException {
    try {
      return parse(JsonParser.parseMap(fileOrValue.readContent(), true));
    } catch (CodecException | IOException e) {
      throw new InvalidConfException(e);
    }
  }

  public static P11SystemConf parse(File file) throws InvalidConfException {
    try {
      return parse(JsonParser.parseMap(file.toPath(), true));
    } catch (CodecException e) {
      throw new InvalidConfException(e);
    }
  }

  public static P11SystemConf parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("modules");
    List<ModuleConf> modules = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      modules.add(ModuleConf.parse(v));
    }

    list = json.getList("mechanismSets");
    List<MechanismSetConf> mechanismSets = null;
    if (list != null) {
      mechanismSets = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        mechanismSets.add(MechanismSetConf.parse(v));
      }
    }

    return new P11SystemConf(modules, mechanismSets);
  }

}
