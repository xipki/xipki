/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Configuration of a PKCS#11 module.
 *
 * @author Lijun Liao
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

    boolean match(P11SlotIdentifier slotId) {
      if (index != null) {
        if (index.intValue() != slotId.getIndex()) {
          return false;
        }
      }

      if (id != null) {
        if (id.longValue() != slotId.getId()) {
          return false;
        }
      }

      return true;
    }

  }

  private static final class P11SingleMechanismFilter {

    private final Set<P11SlotIdFilter> slots;

    private final Collection<Long> mechanisms;

    private P11SingleMechanismFilter(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
      this.slots = slots;
      this.mechanisms = CollectionUtil.isEmpty(mechanisms) ? null : mechanisms;
    }

    public boolean match(P11SlotIdentifier slot) {
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

  } // class SingleFilter

  public static class P11MechanismFilter {

    private final List<P11SingleMechanismFilter> singleFilters;

    P11MechanismFilter() {
      singleFilters = new LinkedList<>();
    }

    void addEntry(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
      Args.notNull(mechanisms, "mechanismis");
      singleFilters.add(new P11SingleMechanismFilter(slots, mechanisms));
    }

    void addAcceptAllEntry(Set<P11SlotIdFilter> slots) {
      singleFilters.add(new P11SingleMechanismFilter(slots, null));
    }

    public boolean isMechanismPermitted(P11SlotIdentifier slotId, long mechanism) {
      Args.notNull(slotId, "slotId");
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

  }

  public static class P11PasswordsRetriever {

    private static final class P11SinglePasswordRetriever {

      private final Set<P11SlotIdFilter> slots;

      private final List<String> passwords;

      private P11SinglePasswordRetriever(Set<P11SlotIdFilter> slots, List<String> passwords) {
        this.slots = slots;
        this.passwords = CollectionUtil.isEmpty(passwords) ? null : passwords;
      }

      public boolean match(P11SlotIdentifier slot) {
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

        List<char[]> ret = new ArrayList<char[]>(passwords.size());
        for (String password : passwords) {
          if (passwordResolver == null) {
            ret.add(password.toCharArray());
          } else {
            ret.add(passwordResolver.resolvePassword(password));
          }
        }

        return ret;
      }

    } // class SingleRetriever

    private final List<P11SinglePasswordRetriever> singleRetrievers;
    private PasswordResolver passwordResolver;

    P11PasswordsRetriever() {
      singleRetrievers = new LinkedList<>();
    }

    void addPasswordEntry(Set<P11SlotIdFilter> slots, List<String> passwords) {
      singleRetrievers.add(new P11SinglePasswordRetriever(slots, passwords));
    }

    public List<char[]> getPassword(P11SlotIdentifier slotId) throws PasswordResolverException {
      Args.notNull(slotId, "slotId");
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

  }

  public static class P11NewObjectConf {

    private boolean ignoreLabel;

    private int idLength = 8;

    private Set<Long> setCertObjectAttributes;

    public P11NewObjectConf(Pkcs11conf.NewObjectConf conf) {
      Boolean bb = conf.getIgnoreLabel();
      this.ignoreLabel = (bb == null) ? false : bb.booleanValue();

      Integer ii = conf.getIdLength();
      this.idLength = (ii == null) ? 8 : ii.intValue();

      List<Pkcs11conf.NewObjectConf.CertAttribute> attrs = conf.getCertAttributes();
      Set<Long> set = new HashSet<>();
      if (attrs != null) {
        for (Pkcs11conf.NewObjectConf.CertAttribute attr : attrs) {
          set.add(attr.getPkcs11CkaCode());
        }
      }
      this.setCertObjectAttributes = Collections.unmodifiableSet(set);
    }

    public P11NewObjectConf() {
      this.setCertObjectAttributes = Collections.emptySet();
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

    public Set<Long> getSetCertObjectAttributes() {
      return setCertObjectAttributes;
    }

    public void setSetCertObjectAttributes(Set<Long> setCertObjectAttributes) {
      this.setCertObjectAttributes =
          Args.notNull(setCertObjectAttributes, "setCertObjectAttributes");
    }

  }

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

  private final P11NewObjectConf newObjectConf;

  public P11ModuleConf(Pkcs11conf.Module moduleType, List<Pkcs11conf.MechanismSet> mechanismSets,
      PasswordResolver passwordResolver) throws InvalidConfException {
    Args.notNull(moduleType, "moduleType");
    Args.notEmpty(mechanismSets, "mechanismSets");
    this.name = moduleType.getName();
    this.readOnly = moduleType.isReadonly();

    String userTypeStr = moduleType.getUser().toUpperCase();
    if ("CKU_USER".equals(userTypeStr)) {
      this.userType = PKCS11Constants.CKU_USER;
    } else if ("CKU_SO".equals(userTypeStr)) {
      this.userType = PKCS11Constants.CKU_SO;
    } else if ("CKU_CONTEXT_SPECIFIC".equals(userTypeStr)) {
      this.userType = PKCS11Constants.CKU_CONTEXT_SPECIFIC;
    } else {
      try {
        if (userTypeStr.startsWith("0X")) {
          this.userType = Long.parseLong(userTypeStr.substring(2), 16);
        } else {
          this.userType = Long.parseLong(userTypeStr);
        }
      } catch (NumberFormatException ex) {
        throw new InvalidConfException("invalid user " + userTypeStr);
      }
    }

    this.maxMessageSize = moduleType.getMaxMessageSize();
    this.type = moduleType.getType();
    if (maxMessageSize < 128) {
      throw new InvalidConfException("invalid maxMessageSize (< 128): " + maxMessageSize);
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
          mech = Functions.mechanismStringToCode(mechStr);
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
          } catch (NumberFormatException ex) {// CHECKSTYLE:SKIP
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

    List<Pkcs11conf.MechanimFilter> mechFilters = moduleType.getMechanismFilters();
    if (mechFilters != null && CollectionUtil.isNotEmpty(mechFilters)) {
      for (Pkcs11conf.MechanimFilter filterType : mechFilters) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(filterType.getSlots());
        String mechanismSetName = filterType.getMechanismSet();

        if (!mechanismSetsMap.containsKey(mechanismSetName)) {
          throw new InvalidConfException("MechanismSet '" +  mechanismSetName
              + "' is not defined");
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
    if (passwordsList != null && CollectionUtil.isNotEmpty(passwordsList)) {
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
  }

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

  public P11PasswordsRetriever getPasswordRetriever() {
    return passwordRetriever;
  }

  public boolean isSlotIncluded(P11SlotIdentifier slotId) {
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
      return included;
    }

    for (P11SlotIdFilter entry : excludeSlots) {
      if (entry.match(slotId)) {
        return false;
      }
    }

    return true;
  }

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
  }

}

