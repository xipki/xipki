// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.KeypairGenEntryWrapper;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages the keypair generation.
 *
 * @author Lijun Liao (xipki)
 * @since  6.0.0
 */

class KeypairGenManager {

  private static final Logger LOG = LoggerFactory.getLogger(KeypairGenManager.class);

  private boolean keypairGenInitialized;

  private final CaManagerImpl manager;

  KeypairGenManager(CaManagerImpl manager) {
    this.manager = manager;
  }

  void reset() {
    keypairGenInitialized = false;
  }

  void close() {
    for (KeypairGenEntryWrapper entry : manager.keypairGens.values()) {
      try {
        entry.getGenerator().close();
      } catch (IOException e) {
        LogUtil.warn(LOG, e, "error closing keypair generator " + entry.getDbEntry().getName());
      }
    }
  }

  void initKeypairGens() throws CaMgmtException {
    if (keypairGenInitialized) {
      return;
    }

    manager.keypairGenDbEntries.clear();
    manager.keypairGens.clear();

    int dbSchemaVersion = manager.getDbSchemaVersion();

    List<KeypairGenEntry> entries;
    if (dbSchemaVersion < 7) {
      throw new CaMgmtException("dbSchemaVersion < 7 unsupported: " + dbSchemaVersion);
    }

    List<String> names = manager.queryExecutor.namesFromTable("KEYPAIR_GEN");
    entries = new ArrayList<>(names.size());
    for (String name : names) {
      entries.add(manager.queryExecutor.createKeypairGen(name));
    }

    for (KeypairGenEntry entry : entries) {
      String name = entry.getName();
      manager.keypairGenDbEntries.put(name, entry);

      KeypairGenEntryWrapper gen = createKeypairGen(entry);
      manager.keypairGens.put(name, gen);
      LOG.info("loaded keypair generation {}", name);
    }

    keypairGenInitialized = true;
  } // method initSigners

  void addKeypairGen(KeypairGenEntry keypairGenEntry) throws CaMgmtException {
    if ("software".equalsIgnoreCase(Args.notNull(keypairGenEntry, "keypairGenEntry").getName())) {
      throw new CaMgmtException("Adding keypair generation 'software' is not allowed");
    }

    manager.assertMasterMode();

    String name = keypairGenEntry.getName();
    CaManagerImpl.checkName(name, "keypair generation name");
    if (manager.keypairGenDbEntries.containsKey(name)) {
      throw new CaMgmtException(StringUtil.concat("keypair generation named ", name, " exists"));
    }

    KeypairGenEntryWrapper gen = createKeypairGen(keypairGenEntry);

    manager.queryExecutor.addKeypairGen(keypairGenEntry);
    manager.keypairGens.put(name, gen);
    manager.keypairGenDbEntries.put(name, keypairGenEntry);
  } // method addKeypairGen

  void removeKeypairGen(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    boolean bo = manager.queryExecutor.deleteRowWithName(name, "KEYPAIR_GEN");
    if (!bo) {
      throw new CaMgmtException("unknown keypair generation " + name);
    }

    for (String caName : manager.caInfos.keySet()) {
      CaInfo caInfo = manager.caInfos.get(caName);
      List<String> names = caInfo.getKeypairGenNames();
      if (names != null && names.contains(name)) {
        ChangeCaEntry changeCaEntry = new ChangeCaEntry(caInfo.getIdent());
        List<String> newNames = new ArrayList<>(names);
        newNames.remove(name);
        changeCaEntry.setKeypairGenNames(newNames);
        manager.queryExecutor.changeCa(changeCaEntry, caInfo.getCaConfColumn(), manager.securityFactory);

        caInfo.getKeypairGenNames().remove(name);
      }
    }

    manager.keypairGenDbEntries.remove(name);
    manager.keypairGens.remove(name);
    LOG.info("removed keypair generation '{}'", name);
  } // method removeKeypairGen

  void changeKeypairGen(String name, String type, String conf) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    KeypairGenEntryWrapper newKeypairGen = manager.queryExecutor.changeKeypairGen(name, type, conf, manager);

    manager.keypairGens.remove(name);
    manager.keypairGenDbEntries.remove(name);

    manager.keypairGenDbEntries.put(name, newKeypairGen.getDbEntry());
    manager.keypairGens.put(name, newKeypairGen);
  } // method changeKeypairGen

  KeypairGenEntryWrapper createKeypairGen(KeypairGenEntry entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    KeypairGenEntryWrapper ret = new KeypairGenEntryWrapper();
    ret.setDbEntry(entry);

    try {
      ret.init(manager.securityFactory, manager.shardId, manager.datasourceMap);
    } catch (ObjectCreationException ex) {
      final String message = "error createKeypairGen";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createKeypairGen

}
