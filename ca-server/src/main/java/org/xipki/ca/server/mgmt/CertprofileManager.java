// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertprofileValidator;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.sdk.CertprofileInfoResponse;
import org.xipki.ca.sdk.KeyType;
import org.xipki.ca.server.IdentifiedCertprofile;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.TripleState;
import org.xipki.util.exception.ObjectCreationException;

import java.util.*;

/**
 * Manages the certificate profiles.
 *
 * @author Lijun Liao (xipki)
 */

class CertprofileManager {

  private static final Logger LOG = LoggerFactory.getLogger(CertprofileManager.class);

  private boolean certprofilesInitialized;

  private final CaManagerImpl manager;

  CertprofileManager(CaManagerImpl manager) {
    this.manager = Args.notNull(manager, "manager");
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

    List<String> names = manager.caConfStore.getProfileNames();
    for (String name : names) {
      CertprofileEntry dbEntry = manager.caConfStore.createCertprofile(name);
      manager.idNameMap.addCertprofile(dbEntry.getIdent());
      dbEntry.setFaulty(true);
      manager.certprofileDbEntries.put(name, dbEntry);

      try {
        IdentifiedCertprofile profile = createCertprofile(dbEntry);
        dbEntry.setFaulty(false);
        manager.certprofiles.put(name, profile);
        LOG.info("loaded certprofile {}", name);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "ERROR loading certprofile " + name);
      }
    }

    certprofilesInitialized = true;
  } // method initCertprofiles

  void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    profileName = Args.toNonBlankLower(profileName, "profileName");
    caName = Args.toNonBlankLower(caName, "caName");

    manager.caConfStore.removeCertprofileFromCa(profileName, caName);

    if (manager.caHasProfiles.containsKey(caName)) {
      Set<CaProfileEntry> set = manager.caHasProfiles.get(caName);
      if (set != null) {
        CaProfileEntry profileEntry = null;
        for (CaProfileEntry entry : set) {
          if (entry.getProfileName().equals(profileName)) {
            profileEntry = entry;
          }
        }

        if (profileEntry != null) {
          set.remove(profileEntry);
        }
      }
    }
  } // method removeCertprofileFromCa

  void addCertprofileToCa(String profileNameAndAlias, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    CaProfileEntry caProfileEntry;
    try {
      caProfileEntry = CaProfileEntry.decode(profileNameAndAlias);
    } catch (Exception ex) {
      throw new CaMgmtException("invalid syntax of profileNameAndAlias '" + profileNameAndAlias + "'", ex);
    }

    String profileName = caProfileEntry.getProfileName();

    profileName = Args.toNonBlankLower(profileName, "profileName");
    caName = Args.toNonBlankLower(caName, "caName");

    NameId ident = manager.idNameMap.getCertprofile(profileName);
    if (ident == null) {
      throw manager.logAndCreateException("unknown Certprofile " + profileName);
    }

    NameId caIdent = manager.idNameMap.getCa(caName);
    if (caIdent == null) {
      throw manager.logAndCreateException("unknown CA " + caName);
    }

    Set<CaProfileEntry> set = manager.caHasProfiles.get(caName);
    if (set == null) {
      set = new HashSet<>();
      manager.caHasProfiles.put(caName, set);
    } else {
      for (CaProfileEntry existingEntry : set) {
        String containedNameOrAlias = existingEntry.containedNameOrAlias(caProfileEntry);
        if (containedNameOrAlias != null) {
          throw manager.logAndCreateException(
              "Certprofile (name or alias) '" + containedNameOrAlias + "' already associated with CA " + caName);
        }
      }
    }

    manager.caConfStore.addCertprofileToCa(ident, caIdent, caProfileEntry.getProfileAliases());
    set.add(caProfileEntry);
  } // method addCertprofileToCa

  void removeCertprofile(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");

    for (String caName : manager.caHasProfiles.keySet()) {
      Set<CaProfileEntry> caHasProfiles = manager.caHasProfiles.get(caName);
      for (CaProfileEntry m : caHasProfiles) {
        if (m.getProfileName().equals(name)) {
          removeCertprofileFromCa(name, caName);
          break;
        }
      }
    }

    boolean bo = manager.caConfStore.deleteProfile(name);
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
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    if (type == null && conf == null) {
      throw new IllegalArgumentException("type and conf cannot be both null");
    }
    NameId ident = manager.idNameMap.getCertprofile(name);
    if (ident == null) {
      throw manager.logAndCreateException("unknown Certprofile " + name);
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedCertprofile profile = manager.caConfStore.changeCertprofile(ident, type, conf, manager);

    manager.certprofileDbEntries.remove(name);
    IdentifiedCertprofile oldProfile = manager.certprofiles.remove(name);
    manager.certprofileDbEntries.put(name, profile.getDbEntry());
    manager.certprofiles.put(name, profile);

    if (oldProfile != null) {
      shutdownCertprofile(oldProfile);
    }
  } // method changeCertprofile

  void addCertprofile(CertprofileEntry certprofileEntry) throws CaMgmtException {
    manager.assertMasterMode();
    String name = Args.notNull(certprofileEntry, "certprofileEntry").getIdent().getName();
    CaManagerImpl.checkName(name, "certprofile name");
    if (manager.certprofileDbEntries.containsKey(name)) {
      throw new CaMgmtException("Certprofile '" + name + "' exists");
    }

    certprofileEntry.setFaulty(true);
    IdentifiedCertprofile profile = Optional.ofNullable(createCertprofile(certprofileEntry)).orElseThrow(
        () -> new CaMgmtException("could not create Certprofile object"));

    certprofileEntry.setFaulty(false);
    manager.certprofiles.put(name, profile);
    manager.caConfStore.addCertprofile(certprofileEntry);
    manager.idNameMap.addCertprofile(certprofileEntry.getIdent());
    manager.certprofileDbEntries.put(name, certprofileEntry);
  } // method addCertprofile

  CertprofileInfoResponse getCertprofileInfo(String profileName) throws OperationException {
    IdentifiedCertprofile profile0 = Optional.ofNullable(manager.getIdentifiedCertprofile(profileName))
        .orElseThrow(() -> new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE));

    Certprofile profile = profile0.getCertprofile();
    Map<ASN1ObjectIdentifier, Certprofile.ExtensionControl> extnControls = profile.getExtensionControls();

    List<String> requiredExtensionsInReq = new LinkedList<>();
    List<String> optionalExtensionsInReq = new LinkedList<>();
    for (Map.Entry<ASN1ObjectIdentifier, Certprofile.ExtensionControl> m : extnControls.entrySet()) {
      TripleState inRequest = m.getValue().getInRequest();
      if (inRequest == null || inRequest == TripleState.forbidden) {
        continue;
      }

      if (m.getValue().isRequired() && inRequest == TripleState.required) {
        requiredExtensionsInReq.add(m.getKey().getId());
      } else {
        optionalExtensionsInReq.add(m.getKey().getId());
      }
    }

    String[] requiredOids = null;
    if (!requiredExtensionsInReq.isEmpty()) {
      requiredOids = requiredExtensionsInReq.toArray(new String[0]);
    }

    String[] optionalOids = null;
    if (!optionalExtensionsInReq.isEmpty()) {
      optionalOids = optionalExtensionsInReq.toArray(new String[0]);
    }

    KeyType[] keyTypes = null;
    Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = profile.getKeyAlgorithms();
    if (keyAlgorithms != null) {
      List<KeyType> keyTypeList = new LinkedList<>();

      for (Map.Entry<ASN1ObjectIdentifier, KeyParametersOption> m : keyAlgorithms.entrySet()) {
        KeyParametersOption params = m.getValue();

        String[] ecCurves = null;
        if (params instanceof KeyParametersOption.ECParamatersOption) {
          // set the curve OIDs,
          Set<ASN1ObjectIdentifier> curveOids = ((KeyParametersOption.ECParamatersOption) params).getCurveOids();
          if (CollectionUtil.isNotEmpty(curveOids)) {
            List<String> curveOidsInText = new LinkedList<>();
            for (ASN1ObjectIdentifier curveOid : curveOids) {
              curveOidsInText.add(curveOid.getId());
            }

            ecCurves = curveOidsInText.toArray(new String[0]);
          }
        }

        keyTypeList.add(new KeyType(m.getKey().getId(), ecCurves));
      }

      if (!keyTypeList.isEmpty()) {
        keyTypes = keyTypeList.toArray(new KeyType[0]);
      }
    }

    return new CertprofileInfoResponse(requiredOids, optionalOids, keyTypes);
  }

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
    String type = Args.notNull(entry, "entry").getType();
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
