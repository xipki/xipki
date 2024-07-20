// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.Passwords;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
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

  public static class P11PasswordsRetriever {

    private static final class P11SinglePasswordRetriever {

      private final Set<P11SlotIdFilter> slots;

      private final String password;

      private P11SinglePasswordRetriever(Set<P11SlotIdFilter> slots, String password) {
        this.slots = slots;
        this.password = password;
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

      public char[] getPassword() throws PasswordResolverException {
        if (password == null) {
          return null;
        }

        return Passwords.resolvePassword(password);
      }

    } // class P11PasswordsRetriever

    private final List<P11SinglePasswordRetriever> singleRetrievers;

    P11PasswordsRetriever() {
      singleRetrievers = new LinkedList<>();
    }

    void addPasswordEntry(Set<P11SlotIdFilter> slots, String password) {
      singleRetrievers.add(new P11SinglePasswordRetriever(slots, password));
    }

    public char[] getPassword(P11SlotId slotId) throws PasswordResolverException {
      Args.notNull(slotId, "slotId");
      if (CollectionUtil.isEmpty(singleRetrievers)) {
        return null;
      }

      for (P11SinglePasswordRetriever sr : singleRetrievers) {
        if (sr.match(slotId)) {
          return sr.getPassword();
        }
      }

      return null;
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

  private final String type;

  private final String nativeLibrary;

  private final Map<String, String> nativeLibraryProperties;

  private final Set<P11SlotIdFilter> excludeSlots;

  private final Set<P11SlotIdFilter> includeSlots;

  private final P11PasswordsRetriever passwordRetriever;

  private final Integer newSessionTimeout;

  private final String userType;

  private boolean readOnly;

  private int maxMessageSize;

  private Integer numSessions;

  private P11NewObjectConf newObjectConf;

  private List<Long> secretKeyTypes;

  private List<Long> keyPairTypes;

  public P11ModuleConf(Pkcs11conf conf)
      throws InvalidConfException {
    this.readOnly = conf.isReadonly();

    this.userType = conf.getUser().toUpperCase();

    this.maxMessageSize = conf.getMaxMessageSize();
    this.type = conf.getType();
    if (maxMessageSize < 256) {
      throw new InvalidConfException("invalid maxMessageSize (< 256): " + maxMessageSize);
    }

    this.numSessions = conf.getNumSessions();
    this.newSessionTimeout = conf.getNewSessionTimeout();

    List<String> list = conf.getSecretKeyTypes();
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

    list = conf.getKeyPairTypes();
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

    // Password retriever
    passwordRetriever = new P11PasswordsRetriever();
    List<Pkcs11conf.PasswordSet> passwordsList = conf.getPasswordSets();
    if (CollectionUtil.isNotEmpty(passwordsList)) {
      for (Pkcs11conf.PasswordSet passwordType : passwordsList) {
        Set<P11SlotIdFilter> slots = getSlotIdFilters(passwordType.getSlots());
        passwordRetriever.addPasswordEntry(slots, passwordType.getPassword());
      }
    }

    includeSlots = getSlotIdFilters(conf.getIncludeSlots());
    excludeSlots = getSlotIdFilters(conf.getExcludeSlots());

    final String osName = System.getProperty("os.name").toLowerCase();

    Pkcs11conf.NativeLibrary matchLibrary = getNativeLibrary(conf, osName);

    this.nativeLibrary = matchLibrary.getPath();
    this.nativeLibraryProperties = matchLibrary.getProperties();

    this.newObjectConf = (conf.getNewObjectConf() == null) ? new P11NewObjectConf()
        : new P11NewObjectConf(conf.getNewObjectConf());
  } // constructor

  private static Pkcs11conf.NativeLibrary getNativeLibrary(Pkcs11conf conf, String osName)
      throws InvalidConfException {
    Pkcs11conf.NativeLibrary matchLibrary = null;
    for (Pkcs11conf.NativeLibrary library : conf.getNativeLibraries()) {
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
      throw new InvalidConfException("could not find PKCS#11 library for OS " + osName);
    }
    return matchLibrary;
  }

  public String getType() {
    return type;
  }

  public String getNativeLibrary() {
    return nativeLibrary;
  }

  public Map<String, String> getNativeLibraryProperties() {
    return nativeLibraryProperties;
  }

  public void setNewObjectConf(P11NewObjectConf newObjectConf) {
    this.newObjectConf = Args.notNull(newObjectConf, "newObjectConf");
  }

  public P11NewObjectConf getNewObjectConf() {
    return newObjectConf;
  }

  public void setMaxMessageSize(int maxMessageSize) {
    this.maxMessageSize = maxMessageSize;
  }

  public int getMaxMessageSize() {
    return maxMessageSize;
  }

  public void setReadOnly(boolean readOnly) {
    this.readOnly = readOnly;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  public String getUserType() {
    return userType;
  }

  public P11PasswordsRetriever getPasswordRetriever() {
    return passwordRetriever;
  }

  public void setNumSessions(Integer numSessions) {
    this.numSessions = numSessions;
  }

  public Integer getNumSessions() {
    return numSessions;
  }

  public Integer getNewSessionTimeout() {
    return newSessionTimeout;
  }

  public void setSecretKeyTypes(List<Long> secretKeyTypes) {
    this.secretKeyTypes = secretKeyTypes;
  }

  public List<Long> getSecretKeyTypes() {
    return secretKeyTypes;
  }

  public void setKeyPairTypes(List<Long> keyPairTypes) {
    this.keyPairTypes = keyPairTypes;
  }

  public List<Long> getKeyPairTypes() {
    return keyPairTypes;
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
      return PKCS11Constants.nameToCode(PKCS11Constants.Category.CKK, str);
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

