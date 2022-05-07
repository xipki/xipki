/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.KeypairGenEntryWrapper;
import org.xipki.util.ObjectCreationException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.toNonBlankLower;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the keypair generation.
 *
 * @author Lijun Liao
 * @since  5.4.0
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

  void initKeypairGens() throws CaMgmtException {
    if (keypairGenInitialized) {
      return;
    }

    manager.keypairGenDbEntries.clear();
    manager.keypairGens.clear();

    int dbSchemaVersion = manager.getDbSchemaVersion();

    List<KeypairGenEntry> entries;
    if (dbSchemaVersion <= 6) {
      KeypairGenEntry entry = new KeypairGenEntry("software", "SOFTWARE", null);
      entries = Collections.singletonList(entry);
    } else {
      List<String> names = manager.queryExecutor.namesFromTable("KEYPAIR_GEN");
      entries = new ArrayList<>(names.size());
      for (String name : names) {
        KeypairGenEntry entry = manager.queryExecutor.createKeypairGen(name);
        entries.add(entry);
      }
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
    notNull(keypairGenEntry, "keypairGenEntry");
    if ("software".equalsIgnoreCase(keypairGenEntry.getName())) {
      throw new CaMgmtException("Adding keypair generation 'software' is not allowed");
    }

    manager.assertMasterMode();

    String name = keypairGenEntry.getName();
    if (manager.keypairGenDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("keypair generation named ", name, " exists"));
    }

    KeypairGenEntryWrapper gen = createKeypairGen(keypairGenEntry);

    manager.queryExecutor.addKeypairGen(keypairGenEntry);
    manager.keypairGens.put(name, gen);
    manager.keypairGenDbEntries.put(name, keypairGenEntry);
  } // method addKeypairGen

  void removeKeypairGen(String name) throws CaMgmtException {
    manager.assertMasterMode();
    manager.assertDbSchemaVersion7on("Removing keypair generation");

    name = toNonBlankLower(name, "name");
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
        manager.queryExecutor.changeCa(changeCaEntry, caInfo.getCaEntry(),
            caInfo.getCaConfColumn(), manager.securityFactory);

        caInfo.getKeypairGenNames().remove(name);
      }
    }

    manager.keypairGenDbEntries.remove(name);
    manager.keypairGens.remove(name);
    LOG.info("removed keypair generation '{}'", name);
  } // method removeKeypairGen

  void changeKeypairGen(String name, String type, String conf)
      throws CaMgmtException {
    manager.assertMasterMode();
    manager.assertDbSchemaVersion7on("Changing keypair generation");

    name = toNonBlankLower(name, "name");
    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    KeypairGenEntryWrapper newKeypairGen = manager.queryExecutor.changeKeypairGen(
        name, type, conf, manager);

    manager.keypairGens.remove(name);
    manager.keypairGenDbEntries.remove(name);

    manager.keypairGenDbEntries.put(name, newKeypairGen.getDbEntry());
    manager.keypairGens.put(name, newKeypairGen);
  } // method changeKeypairGen

  KeypairGenEntryWrapper createKeypairGen(KeypairGenEntry entry) throws CaMgmtException {
    notNull(entry, "entry");
    KeypairGenEntryWrapper ret = new KeypairGenEntryWrapper();

    ret.setDbEntry(entry);

    try {
      ret.init(manager.securityFactory, manager.shardId, manager.datasourceNameConfFileMap);
    } catch (ObjectCreationException ex) {
      final String message = "error createKeypairGen";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createKeypairGen

}
