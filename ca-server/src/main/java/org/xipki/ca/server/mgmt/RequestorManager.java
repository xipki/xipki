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
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.server.RequestorEntryWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.StringUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.xipki.util.Args.*;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the requestors.
 *
 * @author Lijun Liao
 */

class RequestorManager {

  private static final Logger LOG = LoggerFactory.getLogger(RequestorManager.class);

  private boolean requestorsInitialized;

  private final CaManagerImpl manager;

  RequestorManager(CaManagerImpl manager) {
    this.manager = notNull(manager, "manager");
  }

  void reset() {
    requestorsInitialized = false;
  }

  void initRequestors()
      throws CaMgmtException {
    if (requestorsInitialized) {
      return;
    }

    manager.idNameMap.clearRequestor();
    manager.requestorDbEntries.clear();
    manager.requestors.clear();
    List<String> names = manager.queryExecutor.namesFromTable("REQUESTOR");
    for (String name : names) {
      if (RequestorInfo.NAME_BY_CA.equalsIgnoreCase(name)) {
        Integer id = manager.queryExecutor.getRequestorId(name);
        NameId ident = new NameId(id, name);
        manager.byCaRequestor = new RequestorInfo.ByCaRequestorInfo(ident);
        manager.idNameMap.addRequestor(ident);
      } else if (RequestorInfo.NAME_BY_USER.equalsIgnoreCase(name)) {
        Integer id = manager.queryExecutor.getRequestorId(name);
        manager.byUserRequestorId = new NameId(id, name);
        manager.idNameMap.addRequestor(manager.byUserRequestorId);
      } else {
        RequestorEntry requestorDbEntry = manager.queryExecutor.createRequestor(name);
        manager.idNameMap.addRequestor(requestorDbEntry.getIdent());
        manager.requestorDbEntries.put(name, requestorDbEntry);
        RequestorEntryWrapper requestor = new RequestorEntryWrapper();
        requestor.setDbEntry(requestorDbEntry, manager.securityFactory.getPasswordResolver());
        manager.requestors.put(name, requestor);
      }

      LOG.info("loaded requestor {}", name);
    }
    requestorsInitialized = true;
  } // method initRequestors

  void addRequestor(RequestorEntry requestorEntry) throws CaMgmtException {
    manager.assertMasterMode();

    notNull(requestorEntry, "requestorEntry");
    String name = requestorEntry.getIdent().getName();
    if (manager.requestorDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Requestor named ", name, " exists"));
    }

    // encrypt the password
    PasswordResolver pwdResolver = manager.securityFactory.getPasswordResolver();
    if (RequestorEntry.TYPE_PBM.equalsIgnoreCase(requestorEntry.getType())) {
      String conf = requestorEntry.getConf();
      if (!StringUtil.startsWithIgnoreCase(conf, "PBE:")) {
        String encryptedPassword;
        try {
          encryptedPassword = pwdResolver.protectPassword("PBE", conf.toCharArray());
        } catch (PasswordResolverException ex) {
          throw new CaMgmtException("could not encrypt requestor " + name, ex);
        }
        requestorEntry = new RequestorEntry(requestorEntry.getIdent(),
                            requestorEntry.getType(), encryptedPassword);
      }
    }

    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(requestorEntry, pwdResolver);

    manager.queryExecutor.addRequestor(requestorEntry);
    manager.idNameMap.addRequestor(requestorEntry.getIdent());
    manager.requestorDbEntries.put(name, requestorEntry);
    manager.requestors.put(name, requestor);
  } // method addRequestor

  void removeRequestor(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = toNonBlankLower(name, "name");

    for (String caName : manager.caHasRequestors.keySet()) {
      boolean removeMe = false;
      for (CaHasRequestorEntry caHasRequestor : manager.caHasRequestors.get(caName)) {
        if (caHasRequestor.getRequestorIdent().getName().equals(name)) {
          removeMe = true;
          break;
        }
      }

      if (removeMe) {
        removeRequestorFromCa(name, caName);
      }
    }

    if (!manager.queryExecutor.deleteRowWithName(name, "REQUESTOR")) {
      throw new CaMgmtException("unknown requestor " + name);
    }

    manager.idNameMap.removeRequestor(manager.requestorDbEntries.get(name).getIdent().getId());
    manager.requestorDbEntries.remove(name);
    manager.requestors.remove(name);
    LOG.info("removed requestor '{}'", name);
  } // method removeRequestor

  void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    manager.assertMasterMode();

    name = toNonBlankLower(name, "name");
    notBlank(type, "type");
    notBlank(conf, "conf");

    NameId ident = manager.idNameMap.getRequestor(name);
    if (ident == null) {
      throw manager.logAndCreateException(concat("unknown requestor ", name));
    }

    RequestorEntryWrapper requestor = manager.queryExecutor.changeRequestor(ident, type, conf,
        manager.securityFactory.getPasswordResolver());

    manager.requestorDbEntries.remove(name);
    manager.requestors.remove(name);

    manager.requestorDbEntries.put(name, requestor.getDbEntry());
    manager.requestors.put(name, requestor);
  } // method changeRequestor

  void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    requestorName = toNonBlankLower(requestorName, "requestorName");
    caName = toNonBlankLower(caName, "caName");

    if (requestorName.equals(RequestorInfo.NAME_BY_CA)
        || requestorName.equals(RequestorInfo.NAME_BY_USER)) {
      throw new CaMgmtException(concat("removing requestor ", requestorName, " is not permitted"));
    }

    manager.queryExecutor.removeRequestorFromCa(requestorName, caName);
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

  void addRequestorToCa(CaHasRequestorEntry requestor, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    notNull(requestor, "requestor");
    caName = toNonBlankLower(caName, "caName");

    NameId requestorIdent = requestor.getRequestorIdent();
    NameId ident = manager.idNameMap.getRequestor(requestorIdent.getName());
    if (ident == null) {
      throw manager.logAndCreateException(concat("unknown requestor ", requestorIdent.getName()));
    }

    NameId caIdent = manager.idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    // Set the ID of requestor
    requestorIdent.setId(ident.getId());

    Set<CaHasRequestorEntry> cmpRequestors = manager.caHasRequestors.get(caName);
    if (cmpRequestors == null) {
      cmpRequestors = new HashSet<>();
      manager.caHasRequestors.put(caName, cmpRequestors);
    } else {
      for (CaHasRequestorEntry entry : cmpRequestors) {
        String requestorName = requestorIdent.getName();
        if (entry.getRequestorIdent().getName().equals(requestorName)) {
          String msg = concat("Requestor ", requestorName, " already associated with CA ", caName);
          throw manager.logAndCreateException(msg);
        }
      }
    }

    cmpRequestors.add(requestor);
    manager.queryExecutor.addRequestorToCa(requestor, caIdent);
    manager.caHasRequestors.get(caName).add(requestor);
  } // method addRequestorToCa

}
