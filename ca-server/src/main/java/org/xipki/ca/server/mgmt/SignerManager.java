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

import static org.xipki.ca.server.CaUtil.canonicalizeSignerConf;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.toNonBlankLower;
import static org.xipki.util.StringUtil.concat;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.SignerEntryWrapper;
import org.xipki.util.ObjectCreationException;

/**
 * Manages the CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
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

    List<String> names = manager.queryExecutor.namesFromTable("SIGNER");
    for (String name : names) {
      SignerEntry entry = manager.queryExecutor.createSigner(name);
      if (entry == null) {
        LOG.error("could not initialize signer '{}'", name);
        continue;
      }

      entry.setConfFaulty(true);
      manager.signerDbEntries.put(name, entry);

      SignerEntryWrapper signer = createSigner(entry);
      if (signer != null) {
        entry.setConfFaulty(false);
        manager.signers.put(name, signer);
        LOG.info("loaded signer {}", name);
      } else {
        LOG.error("could not load signer {}", name);
      }
    }
    signerInitialized = true;
  } // method initSigners

  void addSigner(SignerEntry signerEntry) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    notNull(signerEntry, "signerEntry");
    String name = signerEntry.getName();
    if (manager.signerDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Signer named ", name, " exists"));
    }

    String conf = signerEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(signerEntry.getType(), conf, null,
          manager.securityFactory);
      if (!conf.equals(newConf)) {
        signerEntry.setConf(newConf);
      }
    }

    SignerEntryWrapper signer = createSigner(signerEntry);
    manager.queryExecutor.addSigner(signerEntry);
    manager.signers.put(name, signer);
    manager.signerDbEntries.put(name, signerEntry);
  } // method addSigner

  void removeSigner(String name) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");
    boolean bo = manager.queryExecutor.deleteRowWithName(name, "SIGNER");
    if (!bo) {
      throw new CaMgmtException("unknown signer " + name);
    }

    for (String caName : manager.caInfos.keySet()) {
      CaInfo caInfo = manager.caInfos.get(caName);
      if (name.equals(caInfo.getCmpResponderName())) {
        caInfo.setCmpResponderName(null);
      }

      if (name.equals(caInfo.getScepResponderName())) {
        caInfo.setScepResponderName(null);
      }

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
    manager.assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");
    if (type == null && conf == null && base64Cert == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    SignerEntryWrapper newResponder = manager.queryExecutor.changeSigner(name, type, conf,
        base64Cert, manager, manager.securityFactory);

    manager.signers.remove(name);
    manager.signerDbEntries.remove(name);
    manager.signerDbEntries.put(name, newResponder.getDbEntry());
    manager.signers.put(name, newResponder);

    for (String caName : manager.scepResponders.keySet()) {
      if (manager.getCa(caName).getScepResponderName().equals(name)) {
        // update the SCEP responder
        manager.scepResponders.get(caName).setResponder(newResponder);
      }
    }
  } // method changeSigner

  SignerEntryWrapper createSigner(SignerEntry entry) throws CaMgmtException {
    notNull(entry, "entry");
    SignerEntryWrapper ret = new SignerEntryWrapper();
    ret.setDbEntry(entry);
    try {
      ret.initSigner(manager.securityFactory);
    } catch (ObjectCreationException ex) {
      final String message = "createSigner";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createSigner

}
