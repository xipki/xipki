// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.server.RequestorEntryWrapper;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.LogUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages the requestors.
 *
 * @author Lijun Liao (xipki)
 */

class RequestorManager {

  private static final Logger LOG =
      LoggerFactory.getLogger(RequestorManager.class);

  private boolean requestorsInitialized;

  private final CaManagerImpl manager;

  RequestorManager(CaManagerImpl manager) {
    this.manager = Args.notNull(manager, "manager");
  }

  void reset() {
    requestorsInitialized = false;
  }

  void initRequestors() throws CaMgmtException {
    if (requestorsInitialized) {
      return;
    }

    manager.idNameMap.clearRequestor();
    manager.requestorDbEntries.clear();
    manager.requestors.clear();
    List<String> names = manager.caConfStore.getRequestorNames();
    for (String name : names) {
      try {
        if (RequestorInfo.NAME_BY_CA.equalsIgnoreCase(name)) {
          Integer id = manager.caConfStore.getRequestorId(name);
          NameId ident = new NameId(id, name);
          manager.byCaRequestor = new RequestorInfo.ByCaRequestorInfo(ident);
          manager.idNameMap.addRequestor(ident);
        } else {
          RequestorEntry requestorDbEntry =
              manager.caConfStore.createRequestor(name);
          manager.idNameMap.addRequestor(requestorDbEntry.getIdent());
          manager.requestorDbEntries.put(name, requestorDbEntry);
          RequestorEntryWrapper requestor = new RequestorEntryWrapper();
          requestor.setDbEntry(requestorDbEntry);
          manager.requestors.put(name, requestor);
        }

        LOG.info("loaded requestor {}", name);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "ERROR loading requestor " + name);
      }
    }
    requestorsInitialized = true;
  } // method initRequestors

  void addRequestor(RequestorEntry requestorEntry) throws CaMgmtException {
    manager.assertMasterMode();

    String name = Args.notNull(requestorEntry, "requestorEntry")
        .getIdent().getName();
    CaManagerImpl.checkName(name, "requestor name");
    if (manager.requestorDbEntries.containsKey(name)) {
      throw new CaMgmtException("Requestor " + name + " exists");
    }

    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(requestorEntry);

    manager.caConfStore.addRequestor(requestorEntry);
    manager.idNameMap.addRequestor(requestorEntry.getIdent());
    manager.requestorDbEntries.put(name, requestorEntry);
    manager.requestors.put(name, requestor);
  } // method addRequestor

  void removeRequestor(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");

    for (String caName : manager.caHasRequestors.keySet()) {
      boolean removeMe = false;
      for (CaHasRequestorEntry caHasRequestor
          : manager.caHasRequestors.get(caName)) {
        if (caHasRequestor.getRequestorIdent().getName().equals(name)) {
          removeMe = true;
          break;
        }
      }

      if (removeMe) {
        removeRequestorFromCa(name, caName);
      }
    }

    if (!manager.caConfStore.deleteRequestor(name)) {
      throw new CaMgmtException("unknown requestor " + name);
    }

    manager.idNameMap.removeRequestor(
        manager.requestorDbEntries.get(name).getIdent().getId());
    manager.requestorDbEntries.remove(name);
    manager.requestors.remove(name);
    LOG.info("removed requestor '{}'", name);
  } // method removeRequestor

  void changeRequestor(String name, String type, String conf)
      throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");
    Args.notBlank(type, "type");
    Args.notBlank(conf, "conf");

    NameId ident = manager.idNameMap.getRequestor(name);
    if (ident == null) {
      throw manager.logAndCreateException("unknown requestor " + name);
    }

    RequestorEntryWrapper requestor =
        manager.caConfStore.changeRequestor(ident, type, conf);

    manager.requestorDbEntries.remove(name);
    manager.requestors.remove(name);

    manager.requestorDbEntries.put(name, requestor.getDbEntry());
    manager.requestors.put(name, requestor);
  } // method changeRequestor

  void removeRequestorFromCa(String requestorName, String caName)
      throws CaMgmtException {
    manager.assertMasterMode();

    requestorName = Args.toNonBlankLower(requestorName, "requestorName");
    caName = Args.toNonBlankLower(caName, "caName");

    if (requestorName.equals(RequestorInfo.NAME_BY_CA)) {
      throw new CaMgmtException("removing requestor " + requestorName
          + " is not permitted");
    }

    manager.caConfStore.removeRequestorFromCa(requestorName, caName);
    if (manager.caHasRequestors.containsKey(caName)) {
      Set<CaHasRequestorEntry> entries = manager.caHasRequestors.get(caName);
      CaHasRequestorEntry entry = null;
      for (CaHasRequestorEntry m : entries) {
        if (m.getRequestorIdent().getName().equals(requestorName)) {
          entry = m;
        }
      }
      entries.remove(entry);
    }
  } // method removeRequestorFromCa

  void addRequestorToCa(CaHasRequestorEntry requestor, String caName)
      throws CaMgmtException {
    manager.assertMasterMode();

    caName = Args.toNonBlankLower(caName, "caName");

    NameId requestorIdent = Args.notNull(requestor, "requestor")
        .getRequestorIdent();
    NameId ident = manager.idNameMap.getRequestor(requestorIdent.getName());
    if (ident == null) {
      throw manager.logAndCreateException(
          "unknown requestor " + requestorIdent.getName());
    }

    NameId caIdent = manager.idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = "unknown CA " + caName;
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    // Set the ID of requestor
    requestorIdent.setId(ident.getId());

    Set<CaHasRequestorEntry> cmpRequestors =
        manager.caHasRequestors.get(caName);
    if (cmpRequestors == null) {
      cmpRequestors = new HashSet<>();
      manager.caHasRequestors.put(caName, cmpRequestors);
    } else {
      for (CaHasRequestorEntry entry : cmpRequestors) {
        String requestorName = requestorIdent.getName();
        if (entry.getRequestorIdent().getName().equals(requestorName)) {
          String msg = "Requestor " + requestorName +
              " already associated with CA " + caName;
          throw manager.logAndCreateException(msg);
        }
      }
    }

    cmpRequestors.add(requestor);
    manager.caConfStore.addRequestorToCa(requestor, caIdent);
    manager.caHasRequestors.get(caName).add(requestor);
  } // method addRequestorToCa

}
