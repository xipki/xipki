// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.util.*;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;
import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

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
        throw new IllegalArgumentException("at least one of index and id may not be null");
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

    private final Set<P11SlotIdFilter> slots;

    private final Collection<Long> mechanisms;

    private P11SingleMechanismFilter(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
      this.slots = slots;
      this.mechanisms = CollectionUtil.isEmpty(mechanisms) ? null : mechanisms;
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

    public boolean isMechanismSupported(long mechanism) {
      if (mechanisms == null) {
        return true;
      }

      return mechanisms.contains(mechanism);
    }

  } // class P11SingleMechanismFilter

  public static class P11MechanismFilter {

    private final List<P11SingleMechanismFilter> singleFilters;

    P11MechanismFilter() {
      singleFilters = new LinkedList<>();
    }

    void addEntry(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
      notNull(mechanisms, "mechanisms");
      singleFilters.add(new P11SingleMechanismFilter(slots, mechanisms));
    }

    void addAcceptAllEntry(Set<P11SlotIdFilter> slots) {
      singleFilters.add(new P11SingleMechanismFilter(slots, null));
    }

    public boolean isMechanismPermitted(P11SlotId slotId, long mechanism) {
      notNull(slotId, "slotId");
      if (CollectionUtil.isEmpty(singleFilters)) {
        return true;
      }

      for (P11SingleMechanismFilter sr : singleFilters) {
        if (sr.match(slotId)) {
          return sr.isMechanismSupported(mechanism);
        }
      }

      return true;
    }

  } // class P11MechanismFilter

  public static class P11PasswordsRetriever {

    private static final class P11SinglePasswordRetriever {

      private final Set<P11SlotIdFilter> slots;

      private final List<String> passwords;

      private P11SinglePasswordRetriever(Set<P11SlotIdFilter> slots, List<String> passwords) {
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

      public List<char[]> getPasswords(PasswordResolver passwordResolver)
          throws PasswordResolverException {
        if (passwords == null) {
          return null;
        }

        List<char[]> ret = new ArrayList<>(passwords.size());
        for (String password : passwords) {
          if (passwordResolver == null) {
            ret.add(password.toCharArray());
          } else {
            ret.add(passwordResolver.resolvePassword(password));
          }
        }

        return ret;
      }

    } // class P11PasswordsRetriever

    private final List<P11SinglePasswordRetriever> singleRetrievers;
    private PasswordResolver passwordResolver;

    P11PasswordsRetriever() {
      singleRetrievers = new LinkedList<>();
    }

    void addPasswordEntry(Set<P11SlotIdFilter> slots, List<String> passwords) {
      singleRetrievers.add(new P11SinglePasswordRetriever(slots, passwords));
    }

    public List<char[]> getPassword(P11SlotId slotId)
        throws PasswordResolverException {
      notNull(slotId, "slotId");
      if (CollectionUtil.isEmpty(singleRetrievers)) {
        return null;
      }

      for (P11SinglePasswordRetriever sr : singleRetrievers) {
        if (sr.match(slotId)) {
          return sr.getPasswords(passwordResolver);
        }
      }

      return null;
    }

    public PasswordResolver getPasswordResolver() {
      return passwordResolver;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver) {
      this.passwordResolver = passwordResolver;
    }

  } // P11PasswordsRetriever

  public static class P11NewObjectConf {

    private boolean ignoreLabel;

    private int idLength = 8;

    public P11NewObjectConf(Pkcs11conf.NewObjectConf conf) {
      Boolean bb = conf.getIgnoreLabel();
      this.ignoreLabel = bb != null && bb;

      Integer ii = conf.getIdLength();
      this.idLength = (ii == null) ? 8 : ii;
    }

    public P11NewObjectConf() {
    }

    public boolean isIgnoreLabel() {
      return ignoreLabel;
    }

    public void setIgnoreLabel(boolean ignoreLabel) {
      this.ignoreLabel = ignoreLabel;
    }

    public int getIdLength() {
      return idLength;
    }

    public void setIdLength(int idLength) {
      this.idLength = idLength;
    }

  } // class P11NewObjectConf

  private static final Logger LOG = LoggerFactory.getLogger(P11ModuleConf.class);

  private final String name;

  private final String type;

  private final String nativeLibrary;

  private final boolean readOnly;

  private final Set<P11SlotIdFilter> excludeSlots;

  private final Set<P11SlotIdFilter> includeSlots;

  private final P11PasswordsRetriever passwordRetriever;

  private final P11MechanismFilter mechanismFilter;

  private final int maxMessageSize;

  private final long userType;

  private final char[] userName;

  private final P11NewObjectConf newObjectConf;

  private final Integer numSessions;

  private final List<Long> secretKeyTypes;

  private final List<Long> keyPairTypes;

  public P11ModuleConf(
      Pkcs11conf.Module moduleType, List<Pkcs11conf.MechanismSet> mechanismSets, PasswordResolver passwordResolver)
      throws InvalidConfException {
    notNull(moduleType, "moduleType");
    notEmpty(mechanismSets, "mechanismSets");
    this.name = moduleType.getName();
    this.readOnly = moduleType.isReadonly();

    String userTypeStr = moduleType.getUser().toUpperCase();
    Long userType = nameToCode(Category.CKU, userTypeStr);
    if (userType == null) {
      try {
        userType = userTypeStr.startsWith("0X")
            ? Long.parseLong(userTypeStr.substring(2), 16) : Long.parseLong(userTypeStr);
      } catch (NumberFormatException ex) {
        throw new InvalidConfException("invalid user " + userTypeStr);
      }
    }
    this.userType = userType;
    this.userName = (moduleType.getUserName() == null) ? null : moduleType.getUserName().toCharArray();

    this.maxMessageSize = moduleType.getMaxMessageSize();
    this.type = moduleType.getType();
    if (maxMessageSize < 256) {
      throw new InvalidConfException("invalid maxMessageSize (< 256): " + maxMessageSize);
    }

    this.numSessions = moduleType.getNumSessions();

    List<String> list = moduleType.getSecretKeyTypes();
    if (list == null) {
      this.secretKeyTypes = null;
    } else {
      List<Long> ll = new ArrayList<>(list.size());
      for (String s : list) {
        Long l = toKeyType(s);
        if (l != null) {
          ll.add(l);
        }
      }
      this.secretKeyTypes = Collections.unmodifiableList(ll);
    }

    list = moduleType.getKeyPairTypes();
    if (list == null) {
      this.keyPairTypes = null;
    } else {
      List<Long> ll = new ArrayList<>(list.size());
      for (String s : list) {
        Long l = toKeyType(s);
        if (l != null) {
          ll.add(l);
        }
      }
      this.keyPairTypes = Collections.unmodifiableList(ll);
    }

    // parse mechanismSets
    Map<String, Set<Long>> mechanismSetsMap = new HashMap<>(mechanismSets.size() * 3 / 2);
    for (Pkcs11conf.MechanismSet m : mechanismSets) {
      String name = m.getName();
      if (mechanismSetsMap.containsKey(name)) {
        throw new InvalidConfException("Duplication mechanismSets named " + name);
      }

      Set<Long> mechanisms = new HashSet<>();
      for (String mechStr : m.getMechanisms()) {
        mechStr = mechStr.trim().toUpperCase();
        if (mechStr.equals("ALL")) {
          mechanisms = null; // accept all mechanisms
          break;
        }

        Long mech = null;
        if (mechStr.startsWith("CKM_")) {
          mech = ckmNameToCode(mechStr);
        } else {
          int radix = 10;
          if (mechStr.startsWith("0X")) {
            radix = 16;
            mechStr = mechStr.substring(2);
          }

          if (mechStr.endsWith("UL")) {
            mechStr = mechStr.substring(0, mechStr.length() - 2);
          } else if (mechStr.endsWith("L")) {
            mechStr = mechStr.substring(0, mechStr.length() - 1);
          }

          try {
            mech = Long.parseLong(mechStr, radix);
          } catch (NumberFormatException ex) {
          }
        }

        if (mech == null) {
          LOG.warn("skipped unknown mechanism '" + mechStr + "'");
        } else {
          mechanisms.add(mech);
        }
      }

      mechanismSetsMap.put(name, mechanisms);
    }

    // Mechanism filter
    mechanismFilter = new P11MechanismFilter();

    List<Pkcs11conf.MechanismFilter> mechFilters = moduleType.getMechanismFilters();
    if (CollectionUtil.isNotEmpty(mechFilters)) {
      for (Pkcs11conf.MechanismFilter filterType : mechFilters) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(filterType.getSlots());
        String mechanismSetName = filterType.getMechanismSet();

        if (!mechanismSetsMap.containsKey(mechanismSetName)) {
          throw new InvalidConfException("MechanismSet '" +  mechanismSetName + "' is not defined");
        }

        Set<Long> mechanisms = mechanismSetsMap.get(mechanismSetName);
        if (mechanisms == null) {
          mechanismFilter.addAcceptAllEntry(slots);
        } else {
          mechanismFilter.addEntry(slots, mechanisms);
        }
      }
    }

    // Password retriever
    passwordRetriever = new P11PasswordsRetriever();
    List<Pkcs11conf.PasswordSet> passwordsList = moduleType.getPasswordSets();
    if (CollectionUtil.isNotEmpty(passwordsList)) {
      passwordRetriever.setPasswordResolver(passwordResolver);
      for (Pkcs11conf.PasswordSet passwordType : passwordsList) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(passwordType.getSlots());
        passwordRetriever.addPasswordEntry(slots, new ArrayList<>(passwordType.getPasswords()));
      }
    }

    includeSlots = getSlotIdFilters(moduleType.getIncludeSlots());
    excludeSlots = getSlotIdFilters(moduleType.getExcludeSlots());

    final String osName = System.getProperty("os.name").toLowerCase();
    String nativeLibraryPath = null;
    for (Pkcs11conf.NativeLibrary library : moduleType.getNativeLibraries()) {
      List<String> osNames = library.getOperationSystems();
      if (CollectionUtil.isEmpty(osNames)) {
        nativeLibraryPath = library.getPath();
      } else {
        for (String entry : osNames) {
          if (osName.contains(entry.toLowerCase())) {
            nativeLibraryPath = library.getPath();
            break;
          }
        }
      }

      if (nativeLibraryPath != null) {
        break;
      }
    } // end for (NativeLibraryType library)

    if (nativeLibraryPath == null) {
      throw new InvalidConfException("could not find PKCS#11 library for OS " + osName);
    }
    this.nativeLibrary = nativeLibraryPath;

    this.newObjectConf = (moduleType.getNewObjectConf() == null) ? new P11NewObjectConf()
        : new P11NewObjectConf(moduleType.getNewObjectConf());
  } // constructor

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

  public String getNativeLibrary() {
    return nativeLibrary;
  }

  public int getMaxMessageSize() {
    return maxMessageSize;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  public long getUserType() {
    return userType;
  }

  public char[] getUserName() {
    return userName;
  }

  public P11PasswordsRetriever getPasswordRetriever() {
    return passwordRetriever;
  }

  public Integer getNumSessions() {
    return numSessions;
  }

  public List<Long> getSecretKeyTypes() {
    return secretKeyTypes;
  }

  public List<Long> getKeyPairTypes() {
    return keyPairTypes;
  }

  public boolean isSlotIncluded(P11SlotId slotId) {
    notNull(slotId, "slotId");
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

  public P11NewObjectConf getP11NewObjectConf() {
    return newObjectConf;
  }

  private static Set<P11SlotIdFilter> getSlotIdFilters(List<Pkcs11conf.Slot> slotTypes)
      throws InvalidConfException {
    if (CollectionUtil.isEmpty(slotTypes)) {
      return null;
    }

    Set<P11SlotIdFilter> filters = new HashSet<>();
    for (Pkcs11conf.Slot slotType : slotTypes) {
      Long slotId = null;
      if (slotType.getId() != null) {
        String str = slotType.getId().trim();
        try {
          slotId = StringUtil.startsWithIgnoreCase(str, "0X")
              ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str);
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

  private static Long toKeyType(String str) {
    if (str.startsWith("CKK_")) {
      return nameToCode(Category.CKK, str);
    } else {
      int radix = 10;
      if (str.startsWith("0X")) {
        radix = 16;
        str = str.substring(2);
      }

      if (str.endsWith("UL")) {
        str = str.substring(0, str.length() - 2);
      } else if (str.endsWith("L")) {
        str = str.substring(0, str.length() - 1);
      }

      try {
        return Long.parseLong(str, radix);
      } catch (NumberFormatException ex) {
        return null;
      }
    }
  }

}

