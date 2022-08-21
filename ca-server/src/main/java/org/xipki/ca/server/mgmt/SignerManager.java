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
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.SignerEntryWrapper;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.*;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static org.xipki.ca.server.CaUtil.canonicalizeSignerConf;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.toNonBlankLower;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the signers.
 *
 * @author Lijun Liao
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
      entry.setConfFaulty(true);
      manager.signerDbEntries.put(name, entry);

      SignerEntryWrapper signer = createSigner(entry);
      entry.setConfFaulty(false);
      manager.signers.put(name, signer);
      LOG.info("loaded signer {}", name);
    }
    signerInitialized = true;
  } // method initSigners

  void addSigner(SignerEntry signerEntry) throws CaMgmtException {
    manager.assertMasterMode();

    notNull(signerEntry, "signerEntry");
    String name = signerEntry.getName();
    if (manager.signerDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Signer named ", name, " exists"));
    }

    String conf = signerEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(conf);
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
    manager.assertMasterMode();

    name = toNonBlankLower(name, "name");
    boolean bo = manager.queryExecutor.deleteRowWithName(name, "SIGNER");
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

    name = toNonBlankLower(name, "name");
    if (type == null && conf == null && base64Cert == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    SignerEntryWrapper newResponder = manager.queryExecutor.changeSigner(name, type, conf, base64Cert, manager);

    manager.signers.remove(name);
    manager.signerDbEntries.remove(name);
    manager.signerDbEntries.put(name, newResponder.getDbEntry());
    manager.signers.put(name, newResponder);
  } // method changeSigner

  SignerEntryWrapper createSigner(SignerEntry entry) throws CaMgmtException {
    notNull(entry, "entry");
    SignerEntryWrapper ret = new SignerEntryWrapper();
    ret.setDbEntry(entry);
    try {
      ret.initSigner(manager.securityFactory);
    } catch (ObjectCreationException ex) {
      final String message = "error createSigner";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createSigner

  String getTokenInfoP11(String moduleName, Integer slotIndex, boolean verbose)
          throws CaMgmtException {
    StringBuilder sb = new StringBuilder();
    final String NL = "\n";
    try {
      P11CryptService p11Service = manager.p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new CaMgmtException("undefined module " + moduleName);
      }

      P11Module module = p11Service.getModule();
      sb.append("module: ").append(moduleName).append(NL);
      sb.append(module.getDescription()).append(NL);

      List<P11SlotIdentifier> slots = module.getSlotIds();
      if (slotIndex == null) {
        output(sb, slots);
      } else {
        P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
        P11Slot slot = module.getSlot(slotId);
        sb.append("Details of slot\n");

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        slot.showDetails(bout, verbose);
        bout.flush();
        sb.append(StringUtil.toUtf8String(bout.toByteArray())).append(NL);
      }
    } catch (P11TokenException | IOException | XiSecurityException ex) {
      throw new CaMgmtException(ex);
    }

    return sb.toString();
  }

  private void output(StringBuilder sb, List<P11SlotIdentifier> slots) {
    // list all slots
    final int n = slots.size();

    if (n == 0 || n == 1) {
      String numText = (n == 0) ? "no" : "1";
      sb.append(numText).append(" slot is configured\n");
    } else {
      sb.append(n).append(" slots are configured\n");
    }

    for (P11SlotIdentifier slotId : slots) {
      sb.append("\tslot[" + slotId.getIndex() + "]: " + slotId.getId()).append("\n");
    }
  }

}
