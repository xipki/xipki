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
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.server.CaIdNameMap;
import org.xipki.ca.server.IdentifiedCertPublisher;
import org.xipki.ca.server.X509Ca;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;

import java.util.*;
import java.util.Map.Entry;

import static org.xipki.util.Args.*;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the publishers.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class PublisherManager {

  private static final Logger LOG = LoggerFactory.getLogger(PublisherManager.class);

  private boolean publishersInitialized;

  private final CaManagerImpl manager;

  PublisherManager(CaManagerImpl manager) {
    this.manager = notNull(manager, "manager");
  }

  void reset() {
    publishersInitialized = false;
  }

  void close() {
    Map<String, IdentifiedCertPublisher> publishers = manager.publishers;
    if (publishers != null) {
      for (Entry<String, IdentifiedCertPublisher> entry : publishers.entrySet()) {
        IdentifiedCertPublisher publisher = entry.getValue();
        shutdownPublisher(publisher);
      }
    }
  }

  void initPublishers() throws CaMgmtException {
    if (publishersInitialized) {
      return;
    }

    Map<String, IdentifiedCertPublisher> publishers = manager.publishers;

    for (Entry<String, IdentifiedCertPublisher> entry: publishers.entrySet()) {
      shutdownPublisher(entry.getValue());
    }
    publishers.clear();
    manager.publisherDbEntries.clear();
    manager.idNameMap.clearPublisher();

    List<String> names = manager.queryExecutor.namesFromTable("PUBLISHER");
    for (String name : names) {
      PublisherEntry dbEntry = manager.queryExecutor.createPublisher(name);

      manager.idNameMap.addPublisher(dbEntry.getIdent());
      dbEntry.setFaulty(true);
      manager.publisherDbEntries.put(name, dbEntry);

      IdentifiedCertPublisher publisher = createPublisher(dbEntry);
      dbEntry.setFaulty(false);
      publishers.put(name, publisher);
      LOG.info("loaded publisher {}", name);
    }

    publishersInitialized = true;
  } // method initPublishers

  void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    publisherName = toNonBlankLower(publisherName, "publisherName");
    caName = toNonBlankLower(caName, "caName");

    manager.queryExecutor.removePublisherFromCa(publisherName, caName);

    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames != null) {
      publisherNames.remove(publisherName);
    }
  } // method removePublisherFromCa

  void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    manager.assertMasterMode();

    publisherName = toNonBlankLower(publisherName, "publisherName");
    caName = toNonBlankLower(caName, "caName");

    CaIdNameMap idNameMap = manager.idNameMap;

    NameId ident = idNameMap.getPublisher(publisherName);
    if (ident == null) {
      throw manager.logAndCreateException(concat("unknown publisher ", publisherName));
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw manager.logAndCreateException(concat("unknown CA ", caName));
    }

    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames == null) {
      publisherNames = new HashSet<>();
      manager.caHasPublishers.put(caName, publisherNames);
    } else {
      if (publisherNames.contains(publisherName)) {
        String msg = concat("publisher ", publisherName, " already associated with CA ", caName);
        throw manager.logAndCreateException(msg);
      }
    }

    IdentifiedCertPublisher publisher = manager.publishers.get(publisherName);
    if (publisher == null) {
      throw new CaMgmtException(concat("publisher '", publisherName, "' is faulty"));
    }

    manager.queryExecutor.addPublisherToCa(idNameMap.getPublisher(publisherName), caIdent);
    publisherNames.add(publisherName);
    manager.caHasPublishers.get(caName).add(publisherName);

    publisher.caAdded(manager.caInfos.get(caName).getCert());
  } // method addPublisherToCa

  void addPublisher(PublisherEntry entry) throws CaMgmtException {
    manager.assertMasterMode();

    notNull(entry, "entry");

    String name = entry.getIdent().getName();
    if (manager.publisherDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Publisher named ", name, " exists"));
    }

    entry.setFaulty(true);
    IdentifiedCertPublisher publisher = createPublisher(entry);
    entry.setFaulty(false);

    manager.queryExecutor.addPublisher(entry);

    manager.publishers.put(name, publisher);
    manager.idNameMap.addPublisher(entry.getIdent());
    manager.publisherDbEntries.put(name, entry);
  } // method addPublisher

  List<PublisherEntry> getPublishersForCa(String caName) {
    caName = toNonBlankLower(caName, "caName");
    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames == null) {
      return Collections.emptyList();
    }

    List<PublisherEntry> ret = new ArrayList<>(publisherNames.size());
    for (String publisherName : publisherNames) {
      ret.add(manager.publisherDbEntries.get(publisherName));
    }

    return ret;
  } // method getPublishersForCa

  PublisherEntry getPublisher(String name) {
    name = toNonBlankLower(name, "name");
    return manager.publisherDbEntries.get(name);
  }

  void removePublisher(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = toNonBlankLower(name, "name");

    for (String caName : manager.caHasPublishers.keySet()) {
      if (manager.caHasPublishers.get(caName).contains(name)) {
        removePublisherFromCa(name, caName);
      }
    }

    boolean bo = manager.queryExecutor.deleteRowWithName(name, "PUBLISHER");
    if (!bo) {
      throw new CaMgmtException("unknown publisher " + name);
    }

    LOG.info("removed publisher '{}'", name);
    manager.publisherDbEntries.remove(name);
    IdentifiedCertPublisher publisher = manager.publishers.remove(name);
    shutdownPublisher(publisher);
  } // method removePublisher

  void changePublisher(String name, String type, String conf) throws CaMgmtException {
    manager.assertMasterMode();

    name = toNonBlankLower(name, "name");

    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }
    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedCertPublisher publisher =
        manager.queryExecutor.changePublisher(name, type, conf, manager);

    IdentifiedCertPublisher oldPublisher = manager.publishers.remove(name);
    shutdownPublisher(oldPublisher);

    manager.publisherDbEntries.put(name, publisher.getDbEntry());
    manager.publishers.put(name, publisher);
  } // method changePublisher

  void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    manager.assertMasterMode();

    caName = toNonBlankLower(caName, "caName");
    positive(numThreads, "numThreads");

    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);
    if (!ca.republishCerts(publisherNames, numThreads)) {
      throw new CaMgmtException(concat("republishing certificates of CA ", caName, " failed"));
    }
  } // method republishCertificates

  void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);

    if (caName == null) {
      if (CollectionUtil.isNotEmpty(publisherNames)) {
        throw new IllegalArgumentException("non-empty publisherNames is not allowed");
      }

      try {
        manager.certstore.clearPublishQueue((NameId) null, (NameId) null);
      } catch (OperationException ex) {
        throw new CaMgmtException(ex.getMessage(), ex);
      }
      return;
    }

    caName = caName.toLowerCase();
    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    ca.clearPublishQueue(publisherNames);
  } // method clearPublishQueue

  List<IdentifiedCertPublisher> getIdentifiedPublishersForCa(String caName) {
    caName = toNonBlankLower(caName, "caName");
    List<IdentifiedCertPublisher> ret = new LinkedList<>();
    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames == null) {
      return ret;
    }

    for (String publisherName : publisherNames) {
      IdentifiedCertPublisher publisher = manager.publishers.get(publisherName);
      ret.add(publisher);
    }
    return ret;
  } // method getIdentifiedPublishersForCa

  void shutdownPublisher(IdentifiedCertPublisher publisher) {
    if (publisher == null) {
      return;
    }

    try {
      publisher.close();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown CertPublisher " + publisher.getIdent());
    }
  } // method shutdownPublisher

  IdentifiedCertPublisher createPublisher(PublisherEntry entry) throws CaMgmtException {
    notNull(entry, "entry");
    String type = entry.getType();

    CertPublisher publisher;
    IdentifiedCertPublisher ret;
    try {
      if (manager.certPublisherFactoryRegister.canCreatePublisher(type)) {
        publisher = manager.certPublisherFactoryRegister.newPublisher(type);
      } else {
        throw new CaMgmtException("unsupported publisher type " + type);
      }

      ret = new IdentifiedCertPublisher(entry, publisher);
      ret.initialize(manager.securityFactory.getPasswordResolver(),
          manager.datasourceNameConfFileMap);
      return ret;
    } catch (ObjectCreationException | CertPublisherException | RuntimeException ex) {
      String msg = "invalid configuration for the publisher " + entry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createPublisher

}
