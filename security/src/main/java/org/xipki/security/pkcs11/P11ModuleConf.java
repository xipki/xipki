// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Configuration of a PKCS#11 module.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class P11ModuleConf {

  private static class P11SlotIdFilter {

    private final Integer index;

    private final Long id;

    P11SlotIdFilter(Integer index, Long id) {
      if (index == null && id == null) {
        throw new IllegalArgumentException(
            "at least one of index and id may not be null");
      }
      this.index = index;
      this.id = id;
    }

    boolean match(P11SlotId slotId) {
      if (index != null) {
        if (index != slotId.getIndex()) {
          return false;
        }
      }

      if (id != null) {
        return id == slotId.getId();
      }

      return true;
    }

  } // class P11SlotIdFilter

  private static final class P11SingleMechanismFilter {

    private static final Object NULL_MODULE = new Object();

    private final Set<P11SlotIdFilter> slots;

    private final Collection<String> includeMechanisms;

    private final Collection<String> excludeMechanisms;

    private Object module;

    private final Set<Long> includeMechanismCodes = new HashSet<>();

    private final Set<Long> excludeMechanismCodes = new HashSet<>();

    private P11SingleMechanismFilter(
        Set<P11SlotIdFilter> slots, Collection<String> includeMechanisms,
        Collection<String> excludeMechanisms) {
      this.slots = slots;

      Set<String> mechs = null;
      if (includeMechanisms != null) {
        mechs = toUpper(includeMechanisms);
        if (mechs.contains("ALL")) {
          mechs = null;
        }
      }
      this.includeMechanisms = mechs;
      this.excludeMechanisms = (excludeMechanisms == null) ? null :
          toUpper(excludeMechanisms);
    }

    private static Set<String> toUpper(Collection<String> c) {
      Set<String> mechs = new HashSet<>();
      for (String s : c) {
        mechs.add(s.toUpperCase(Locale.US));
      }
      return mechs;
    }

    public boolean match(P11SlotId slot) {
      if (slots == null) {
        return true;
      }
      for (P11SlotIdFilter m : slots) {
        if (m.match(slot)) {
          return true;
        }
      }

      return false;
    }

    public boolean isMechanismSupported(long mechanism, PKCS11Module module) {
      if (includeMechanisms == null && excludeMechanisms == null) {
        return true;
      }

      synchronized (this) {
        boolean computeCodes = (module != null) ? (this.module != module)
            : (this.module != NULL_MODULE);

        if (computeCodes) {
          includeMechanismCodes.clear();
          excludeMechanismCodes.clear();

          if (includeMechanisms != null) {
            for (String mechName : includeMechanisms) {
              Long mechCode = (module != null)
                  ? module.nameToCode(Category.CKM, mechName)
                  : PKCS11T.ckmNameToCode(mechName);
              if (mechCode != null) {
                includeMechanismCodes.add(mechCode);
              }
            }
          }

          if (excludeMechanisms != null) {
            for (String mechName : excludeMechanisms) {
              Long mechCode = (module != null)
                  ? module.nameToCode(Category.CKM, mechName)
                  : PKCS11T.ckmNameToCode(mechName);
              if (mechCode != null) {
                excludeMechanismCodes.add(mechCode);
              }
            }
          }

          this.module = (module != null) ? module : NULL_MODULE;
        }
      }

      if (excludeMechanismCodes.contains(mechanism)) {
        return false;
      }

      return includeMechanisms == null ||
          includeMechanismCodes.contains(mechanism);
    }

  } // class P11SingleMechanismFilter

  public static class P11MechanismFilter {

    private final List<P11SingleMechanismFilter> singleFilters;

    P11MechanismFilter() {
      singleFilters = new LinkedList<>();
    }

    void addEntry(Set<P11SlotIdFilter> slots,
                  Collection<String> includeMechanisms,
                  Collection<String> excludeMechanisms) {
      singleFilters.add(new P11SingleMechanismFilter(
          slots, includeMechanisms, excludeMechanisms));
    }

    public boolean isMechanismPermitted(
        P11SlotId slotId, long mechanism, PKCS11Module module) {
      Args.notNull(slotId, "slotId");
      if (CollectionUtil.isEmpty(singleFilters)) {
        return true;
      }

      for (P11SingleMechanismFilter sr : singleFilters) {
        if (sr.match(slotId)) {
          return sr.isMechanismSupported(mechanism, module);
        }
      }

      return true;
    }

  } // class P11MechanismFilter

  public static class P11PasswordsRetriever {

    private static final class P11SinglePasswordRetriever {

      private final Set<P11SlotIdFilter> slots;

      private final List<String> passwords;

      private P11SinglePasswordRetriever(
          Set<P11SlotIdFilter> slots, List<String> passwords) {
        this.slots = slots;
        this.passwords = CollectionUtil.isEmpty(passwords) ? null : passwords;
      }

      public boolean match(P11SlotId slot) {
        if (slots == null) {
          return true;
        }

        for (P11SlotIdFilter m : slots) {
          if (m.match(slot)) {
            return true;
          }
        }

        return false;
      }

      public List<String> getPasswords() throws PasswordResolverException {
        if (passwords == null) {
          return null;
        }

        List<String> ret = new ArrayList<>(passwords.size());
        for (String password : passwords) {
          char[] chars = Passwords.resolvePassword(password);
          ret.add(chars == null ? null : new String(chars));
        }

        return ret;
      }

    } // class P11PasswordsRetriever

    private final List<P11SinglePasswordRetriever> singleRetrievers;

    P11PasswordsRetriever() {
      singleRetrievers = new LinkedList<>();
    }

    void addPasswordEntry(Set<P11SlotIdFilter> slots, List<String> passwords) {
      singleRetrievers.add(new P11SinglePasswordRetriever(slots, passwords));
    }

    public List<String> getPassword(P11SlotId slotId)
        throws PasswordResolverException {
      Args.notNull(slotId, "slotId");
      if (CollectionUtil.isEmpty(singleRetrievers)) {
        return null;
      }

      for (P11SinglePasswordRetriever sr : singleRetrievers) {
        if (sr.match(slotId)) {
          return sr.getPasswords();
        }
      }

      return null;
    }

  } // P11PasswordsRetriever

  private static final Logger LOG =
      LoggerFactory.getLogger(P11ModuleConf.class);

  private final String name;

  private final String nativeLibrary;

  private final Map<String, String> nativeLibraryProperties;

  private final Set<P11SlotIdFilter> excludeSlots;

  private final Set<P11SlotIdFilter> includeSlots;

  private final P11PasswordsRetriever passwordRetriever;

  private final P11MechanismFilter mechanismFilter;

  private final Integer newSessionTimeout;

  private final String userType;

  private final String userName;

  private final boolean readOnly;

  private final int maxMessageSize;

  private final Integer numSessions;

  public P11ModuleConf(
      P11SystemConf.ModuleConf moduleType,
      List<P11SystemConf.MechanismSetConf> mechanismSets)
      throws InvalidConfException {
    this.name = Args.notNull(moduleType, "moduleType").getName();
    this.readOnly = moduleType.isReadonly();

    this.userType = moduleType.getUser().toUpperCase();
    this.userName = (moduleType.getUserName() == null) ? null
        : moduleType.getUserName();

    this.maxMessageSize = moduleType.getMaxMessageSize();
    if (maxMessageSize < 256) {
      throw new InvalidConfException(
          "invalid maxMessageSize (< 256): " + maxMessageSize);
    }

    this.numSessions = moduleType.getNumSessions();
    this.newSessionTimeout = moduleType.getNewSessionTimeout();

    Map<String, P11SystemConf.MechanismSetConf> mechanismSetsMap =
        new HashMap<>();
    // parse mechanismSets
    if (mechanismSets != null) {
      for (P11SystemConf.MechanismSetConf m : mechanismSets) {
        String name = m.getName();
        if (mechanismSetsMap.containsKey(name)) {
          throw new InvalidConfException(
              "Duplication mechanismSets named " + name);
        }

        mechanismSetsMap.put(name, m);
      }
    }

    // Mechanism filter
    mechanismFilter = new P11MechanismFilter();

    List<P11SystemConf.MechanismFilterConf> mechFilters =
        moduleType.getMechanismFilters();
    if (CollectionUtil.isNotEmpty(mechFilters)) {
      for (P11SystemConf.MechanismFilterConf filterType : mechFilters) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(filterType.getSlots());
        String mechanismSetName = filterType.getMechanismSet();

        P11SystemConf.MechanismSetConf mechanismSet =
            mechanismSetsMap.get(mechanismSetName);
        if (mechanismSet == null) {
          throw new InvalidConfException("MechanismSet '" +
              mechanismSetName + "' is not defined");
        } else {
          mechanismFilter.addEntry(slots, mechanismSet.getMechanisms(),
              mechanismSet.getExcludeMechanisms());
        }
      }
    }

    // Password retriever
    passwordRetriever = new P11PasswordsRetriever();
    List<P11SystemConf.PasswordSetConf> passwordsList =
        moduleType.getPasswordSets();
    if (CollectionUtil.isNotEmpty(passwordsList)) {
      for (P11SystemConf.PasswordSetConf passwordType : passwordsList) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(passwordType.getSlots());
        passwordRetriever.addPasswordEntry(slots,
            new ArrayList<>(passwordType.getPasswords()));
      }
    }

    includeSlots = getSlotIdFilters(moduleType.getIncludeSlots());
    excludeSlots = getSlotIdFilters(moduleType.getExcludeSlots());

    final String osName = System.getProperty("os.name").toLowerCase();

    P11SystemConf.NativeLibraryConf matchLibrary =
        getNativeLibrary(moduleType, osName);

    this.nativeLibrary = matchLibrary.getPath();
    this.nativeLibraryProperties = matchLibrary.getProperties();
  } // constructor

  private static P11SystemConf.NativeLibraryConf getNativeLibrary(
      P11SystemConf.ModuleConf moduleType, String osName)
          throws InvalidConfException {
    P11SystemConf.NativeLibraryConf matchLibrary = null;
    for (P11SystemConf.NativeLibraryConf library
        : moduleType.getNativeLibraries()) {
      List<String> osNames = library.getOperationSystems();
      if (CollectionUtil.isEmpty(osNames)) {
        matchLibrary = library;
      } else {
        for (String entry : osNames) {
          if (osName.contains(entry.toLowerCase())) {
            matchLibrary = library;
            break;
          }
        }
      }
    }

    if (matchLibrary == null) {
      throw new InvalidConfException(
          "could not find PKCS#11 library for OS " + osName);
    }
    return matchLibrary;
  }

  public String getName() {
    return name;
  }

  public String getNativeLibrary() {
    return nativeLibrary;
  }

  public Map<String, String> getNativeLibraryProperties() {
    return nativeLibraryProperties;
  }

  public int getMaxMessageSize() {
    return maxMessageSize;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  public String getUserType() {
    return userType;
  }

  public String getUserName() {
    return userName;
  }

  public P11PasswordsRetriever getPasswordRetriever() {
    return passwordRetriever;
  }

  public Integer getNumSessions() {
    return numSessions;
  }

  public Integer getNewSessionTimeout() {
    return newSessionTimeout;
  }

  public boolean isSlotIncluded(P11SlotId slotId) {
    Args.notNull(slotId, "slotId");
    boolean included;
    if (CollectionUtil.isEmpty(includeSlots)) {
      included = true;
    } else {
      included = false;
      for (P11SlotIdFilter entry : includeSlots) {
        if (entry.match(slotId)) {
          included = true;
          break;
        }
      }
    }

    if (!included) {
      return false;
    }

    if (CollectionUtil.isEmpty(excludeSlots)) {
      return true;
    }

    for (P11SlotIdFilter entry : excludeSlots) {
      if (entry.match(slotId)) {
        return false;
      }
    }

    return true;
  } // method isSlotIncluded

  public P11MechanismFilter getP11MechanismFilter() {
    return mechanismFilter;
  }

  private static Set<P11SlotIdFilter> getSlotIdFilters(
      List<P11SystemConf.SlotConf> slotTypes) throws InvalidConfException {
    if (CollectionUtil.isEmpty(slotTypes)) {
      return null;
    }

    Set<P11SlotIdFilter> filters = new HashSet<>();
    for (P11SystemConf.SlotConf slotType : slotTypes) {
      Long slotId = null;
      if (slotType.getId() != null) {
        String str = slotType.getId().trim();
        try {
          boolean hex = StringUtil.startsWithIgnoreCase(str, "0X");
          slotId = Long.parseLong(
              hex ? str.substring(2) : str, hex ? 16 : 10);
        } catch (NumberFormatException ex) {
          String message = "invalid slotId '" + str + "'";
          LOG.error(message);
          throw new InvalidConfException(message);
        }
      }
      filters.add(new P11SlotIdFilter(slotType.getIndex(), slotId));
    }

    return filters;
  } // method getSlotIdFilters

}

