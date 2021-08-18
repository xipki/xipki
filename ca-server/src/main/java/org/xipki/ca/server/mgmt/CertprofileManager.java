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

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertprofileValidator;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.server.IdentifiedCertprofile;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.toNonBlankLower;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the certificate profiles.
 *
 * @author Lijun Liao
 */

class CertprofileManager {

  private static final Logger LOG = LoggerFactory.getLogger(CertprofileManager.class);

  private boolean certprofilesInitialized;

  private final CaManagerImpl manager;

  CertprofileManager(CaManagerImpl manager) {
    this.manager = notNull(manager, "manager");
  }

  void reset() {
    certprofilesInitialized = false;
  }

  void close() {
    for (String name : manager.certprofiles.keySet()) {
      IdentifiedCertprofile certprofile = manager.certprofiles.get(name);
      shutdownCertprofile(certprofile);
    }
  }

  void initCertprofiles() throws CaMgmtException {
    if (certprofilesInitialized) {
      return;
    }

    for (String name : manager.certprofiles.keySet()) {
      shutdownCertprofile(manager.certprofiles.get(name));
    }
    manager.certprofileDbEntries.clear();
    manager.idNameMap.clearCertprofile();
    manager.certprofiles.clear();

    List<String> names = manager.queryExecutor.namesFromTable("PROFILE");
    for (String name : names) {
      CertprofileEntry dbEntry = manager.queryExecutor.createCertprofile(name);
      if (dbEntry == null) {
        LOG.error("could not initialize Certprofile '{}'", name);
        continue;
      }

      manager.idNameMap.addCertprofile(dbEntry.getIdent());
      dbEntry.setFaulty(true);
      manager.certprofileDbEntries.put(name, dbEntry);

      IdentifiedCertprofile profile = createCertprofile(dbEntry);
      if (profile != null) {
        dbEntry.setFaulty(false);
        manager.certprofiles.put(name, profile);
        LOG.info("loaded certprofile {}", name);
      } else {
        LOG.error("could not load certprofile {}", name);
      }
    }

    certprofilesInitialized = true;
  } // method initCertprofiles

  void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    profileName = toNonBlankLower(profileName, "profileName");
    caName = toNonBlankLower(caName, "caName");

    manager.queryExecutor.removeCertprofileFromCa(profileName, caName);

    if (manager.caHasProfiles.containsKey(caName)) {
      Set<String> set = manager.caHasProfiles.get(caName);
      if (set != null) {
        set.remove(profileName);
      }
    }
  } // method removeCertprofileFromCa

  void addCertprofileToCa(String profileName, String caName) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    profileName = toNonBlankLower(profileName, "profileName");
    caName = toNonBlankLower(caName, "caName");

    NameId ident = manager.idNameMap.getCertprofile(profileName);
    if (ident == null) {
      throw manager.logAndCreateException(concat("unknown Certprofile ", profileName));
    }

    NameId caIdent = manager.idNameMap.getCa(caName);
    if (caIdent == null) {
      throw manager.logAndCreateException(concat("unknown CA ", caName));
    }

    Set<String> set = manager.caHasProfiles.get(caName);
    if (set == null) {
      set = new HashSet<>();
      manager.caHasProfiles.put(caName, set);
    } else {
      if (set.contains(profileName)) {
        throw manager.logAndCreateException(
            concat("Certprofile ", profileName, " already associated with CA ", caName));
      }
    }

    if (!manager.certprofiles.containsKey(profileName)) {
      throw new CaMgmtException(concat("certprofile '", profileName, "' is faulty"));
    }

    manager.queryExecutor.addCertprofileToCa(ident, caIdent);
    set.add(profileName);
  } // method addCertprofileToCa

  void removeCertprofile(String name) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");

    for (String caName : manager.caHasProfiles.keySet()) {
      if (manager.caHasProfiles.get(caName).contains(name)) {
        removeCertprofileFromCa(name, caName);
      }
    }

    boolean bo = manager.queryExecutor.deleteRowWithName(name, "PROFILE");
    if (!bo) {
      throw new CaMgmtException("unknown profile " + name);
    }

    LOG.info("removed profile '{}'", name);
    manager.idNameMap.removeCertprofile(manager.certprofileDbEntries.get(name).getIdent().getId());
    manager.certprofileDbEntries.remove(name);
    IdentifiedCertprofile profile = manager.certprofiles.remove(name);
    shutdownCertprofile(profile);
  } // method removeCertprofile

  void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");
    if (type == null && conf == null) {
      throw new IllegalArgumentException("type and conf cannot be both null");
    }
    NameId ident = manager.idNameMap.getCertprofile(name);
    if (ident == null) {
      throw manager.logAndCreateException(concat("unknown Certprofile ", name));
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedCertprofile profile =
        manager.queryExecutor.changeCertprofile(ident, type, conf, manager);

    manager.certprofileDbEntries.remove(name);
    IdentifiedCertprofile oldProfile = manager.certprofiles.remove(name);
    manager.certprofileDbEntries.put(name, profile.getDbEntry());
    manager.certprofiles.put(name, profile);

    if (oldProfile != null) {
      shutdownCertprofile(oldProfile);
    }
  } // method changeCertprofile

  void addCertprofile(CertprofileEntry certprofileEntry) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    notNull(certprofileEntry, "certprofileEntry");
    String name = certprofileEntry.getIdent().getName();
    if (manager.certprofileDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Certprofile named ", name, " exists"));
    }

    certprofileEntry.setFaulty(true);
    IdentifiedCertprofile profile = createCertprofile(certprofileEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create Certprofile object");
    }

    certprofileEntry.setFaulty(false);
    manager.certprofiles.put(name, profile);
    manager.queryExecutor.addCertprofile(certprofileEntry);
    manager.idNameMap.addCertprofile(certprofileEntry.getIdent());
    manager.certprofileDbEntries.put(name, certprofileEntry);
  } // method addCertprofile

  void shutdownCertprofile(IdentifiedCertprofile profile) {
    if (profile == null) {
      return;
    }

    try {
      profile.close();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown Certprofile " + profile.getIdent());
    }
  } // method shutdownCertprofile

  IdentifiedCertprofile createCertprofile(CertprofileEntry entry) throws CaMgmtException {
    notNull(entry, "entry");

    String type = entry.getType();
    if (!manager.certprofileFactoryRegister.canCreateProfile(type)) {
      throw new CaMgmtException("unsupported cert profile type " + type);
    }

    try {
      Certprofile profile = manager.certprofileFactoryRegister.newCertprofile(type);
      IdentifiedCertprofile identifiedCertprofile = new IdentifiedCertprofile(entry, profile);
      try {
        CertprofileValidator.validate(profile);
      } catch (CertprofileException ex) {
        LogUtil.warn(LOG, ex, "validating certprofile " + entry.getIdent().getName() + " failed");
      }
      return identifiedCertprofile;
    } catch (ObjectCreationException | CertprofileException ex) {
      String msg = "could not initialize Certprofile " + entry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createCertprofile

}
