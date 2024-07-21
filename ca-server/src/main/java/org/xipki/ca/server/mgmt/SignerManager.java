// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.CaUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.util.List;

/**
 * Manages the signers.
 *
 * @author Lijun Liao (xipki)
 */

class SignerManager {

  private static final Logger LOG = LoggerFactory.getLogger(SignerManager.class);

  private boolean signerInitialized;

  private final CaManagerImpl manager;

  SignerManager(CaManagerImpl manager) {
    this.manager = manager;
  }

  void reset() {
    signerInitialized = false;
  }

  void initSigners() throws CaMgmtException {
    if (signerInitialized) {
      return;
    }

    manager.signerDbEntries.clear();
    manager.signers.clear();

    List<String> names = manager.caConfStore.getSignerNames();
    for (String name : names) {
      SignerEntry signer = manager.caConfStore.createSigner(name);
      signer.setFaulty(true);
      manager.signerDbEntries.put(name, signer);

      createSigner(signer);
      signer.setFaulty(false);
      manager.signers.put(name, signer);
      LOG.info("loaded signer {}", name);
    }
    signerInitialized = true;
  } // method initSigners

  void addSigner(SignerEntry signerEntry) throws CaMgmtException {
    manager.assertMasterMode();

    String name = Args.notNull(signerEntry, "signerEntry").getName();
    CaManagerImpl.checkName(name, "signer name");
    if (manager.signerDbEntries.containsKey(name)) {
      throw new CaMgmtException(StringUtil.concat("Signer named ", name, " exists"));
    }

    String conf = signerEntry.getConf();
    if (conf != null) {
      String newConf = CaUtil.canonicalizeSignerConf(conf);
      if (!conf.equals(newConf)) {
        signerEntry.setConf(newConf);
      }
    }

    createSigner(signerEntry);
    manager.caConfStore.addSigner(signerEntry);
    manager.signers.put(name, signerEntry);
    manager.signerDbEntries.put(name, signerEntry);
  } // method addSigner

  void removeSigner(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    boolean bo = manager.caConfStore.deleteSigner(name);
    if (!bo) {
      throw new CaMgmtException("unknown signer " + name);
    }

    for (String caName : manager.caInfos.keySet()) {
      CaInfo caInfo = manager.caInfos.get(caName);
      if (name.equals(caInfo.getCrlSignerName())) {
        caInfo.setCrlSignerName(null);
      }

    }

    manager.signerDbEntries.remove(name);
    manager.signers.remove(name);
    LOG.info("removed signer '{}'", name);
  } // method removeSigner

  void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    if (type == null && conf == null && base64Cert == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    SignerEntry newSigner = manager.caConfStore.changeSigner(name, type, conf, base64Cert, manager);

    manager.signers.remove(name);
    manager.signerDbEntries.remove(name);
    manager.signerDbEntries.put(name, newSigner);
    manager.signers.put(name, newSigner);
  } // method changeSigner

  void createSigner(SignerEntry entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    try {
      entry.initSigner(manager.securityFactory);
    } catch (ObjectCreationException ex) {
      final String message = "error createSigner";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
  } // method createSigner

}
