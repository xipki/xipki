// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.server.CaIdNameMap;
import org.xipki.ca.server.IdentifiedCertPublisher;
import org.xipki.ca.server.X509Ca;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.CertPublisherException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.misc.StringUtil;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Manages the publishers.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class PublisherManager {

  private static final Logger LOG =
      LoggerFactory.getLogger(PublisherManager.class);

  private boolean publishersInitialized;

  private final CaManagerImpl manager;

  PublisherManager(CaManagerImpl manager) {
    this.manager = Args.notNull(manager, "manager");
  }

  void reset() {
    publishersInitialized = false;
  }

  void close() {
    Map<String, IdentifiedCertPublisher> publishers = manager.publishers;
    for (Entry<String, IdentifiedCertPublisher> entry : publishers.entrySet()) {
      IdentifiedCertPublisher publisher = entry.getValue();
      shutdownPublisher(publisher);
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

    List<String> names = manager.caConfStore.getPublisherNames();
    for (String name : names) {
      PublisherEntry dbEntry = manager.caConfStore.createPublisher(name);

      manager.idNameMap.addPublisher(dbEntry.getIdent());
      dbEntry.faulty(true);
      manager.publisherDbEntries.put(name, dbEntry);

      try {
        IdentifiedCertPublisher publisher = createPublisher(dbEntry);
        dbEntry.faulty(false);
        publishers.put(name, publisher);
        LOG.info("loaded publisher {}", name);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "ERROR loading publisher " + name);
      }
    }

    publishersInitialized = true;
  } // method initPublishers

  void removePublisherFromCa(String publisherName, String caName)
      throws CaMgmtException {
    manager.assertMasterMode();

    publisherName = Args.toNonBlankLower(publisherName, "publisherName");
    caName = Args.toNonBlankLower(caName, "caName");

    manager.caConfStore.removePublisherFromCa(publisherName, caName);

    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames != null) {
      publisherNames.remove(publisherName);
    }
  } // method removePublisherFromCa

  void addPublisherToCa(String publisherName, String caName)
      throws CaMgmtException {
    manager.assertMasterMode();

    publisherName = Args.toNonBlankLower(publisherName, "publisherName");
    caName = Args.toNonBlankLower(caName, "caName");

    CaIdNameMap idNameMap = manager.idNameMap;

    NameId ident = idNameMap.getPublisher(publisherName);
    if (ident == null) {
      throw manager.logAndCreateException(StringUtil.concat(
          "unknown publisher ", publisherName));
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw manager.logAndCreateException(StringUtil.concat(
          "unknown CA ", caName));
    }

    Set<String> publisherNames = manager.caHasPublishers.get(caName);
    if (publisherNames == null) {
      publisherNames = new HashSet<>();
      manager.caHasPublishers.put(caName, publisherNames);
    } else {
      if (publisherNames.contains(publisherName)) {
        String msg = StringUtil.concat("publisher ", publisherName,
            " already associated with CA ", caName);
        throw manager.logAndCreateException(msg);
      }
    }

    IdentifiedCertPublisher publisher = manager.publishers.get(publisherName);
    if (publisher == null) {
      throw new CaMgmtException(StringUtil.concat(
          "publisher '", publisherName, "' is faulty"));
    }

    manager.caConfStore.addPublisherToCa(
        idNameMap.getPublisher(publisherName), caIdent);
    publisherNames.add(publisherName);
    manager.caHasPublishers.get(caName).add(publisherName);

    publisher.caAdded(manager.caInfos.get(caName).getCert());
  } // method addPublisherToCa

  void addPublisher(PublisherEntry entry) throws CaMgmtException {
    manager.assertMasterMode();

    String name = Args.notNull(entry, "entry").getIdent().getName();
    CaManagerImpl.checkName(name, "publisher name");
    if (manager.publisherDbEntries.containsKey(name)) {
      throw new CaMgmtException(StringUtil.concat(
          "Publisher named ", name, " exists"));
    }

    entry.faulty(true);
    IdentifiedCertPublisher publisher = createPublisher(entry);
    entry.faulty(false);

    manager.caConfStore.addPublisher(entry);

    manager.publishers.put(name, publisher);
    manager.idNameMap.addPublisher(entry.getIdent());
    manager.publisherDbEntries.put(name, entry);
  } // method addPublisher

  void removePublisher(String name) throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");

    for (String caName : manager.caHasPublishers.keySet()) {
      if (manager.caHasPublishers.get(caName).contains(name)) {
        removePublisherFromCa(name, caName);
      }
    }

    boolean bo = manager.caConfStore.deletePublisher(name);
    if (!bo) {
      throw new CaMgmtException("unknown publisher " + name);
    }

    LOG.info("removed publisher '{}'", name);
    manager.publisherDbEntries.remove(name);
    IdentifiedCertPublisher publisher = manager.publishers.remove(name);
    shutdownPublisher(publisher);
  } // method removePublisher

  void changePublisher(String name, String type, String conf)
      throws CaMgmtException {
    manager.assertMasterMode();

    name = Args.toNonBlankLower(name, "name");

    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }
    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedCertPublisher publisher =
        manager.caConfStore.changePublisher(name, type, conf, manager);

    IdentifiedCertPublisher oldPublisher = manager.publishers.remove(name);
    shutdownPublisher(oldPublisher);

    manager.publisherDbEntries.put(name, publisher.getDbEntry());
    manager.publishers.put(name, publisher);
  } // method changePublisher

  void republishCertificates(String caName, List<String> publisherNames,
                             int numThreads)
      throws CaMgmtException {
    manager.assertMasterMode();

    caName = Args.toNonBlankLower(caName, "caName");
    Args.positive(numThreads, "numThreads");

    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(StringUtil.concat(
          "could not find CA named ", caName));
    }

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);
    if (!ca.republishCerts(publisherNames, numThreads)) {
      throw new CaMgmtException(StringUtil.concat(
          "republishing certificates of CA ", caName, " failed"));
    }
  } // method republishCertificates

  List<IdentifiedCertPublisher> getIdentifiedPublishersForCa(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
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
      LogUtil.warn(LOG, ex, "could not shutdown CertPublisher "
          + publisher.getIdent());
    }
  } // method shutdownPublisher

  IdentifiedCertPublisher createPublisher(PublisherEntry entry)
      throws CaMgmtException {
    String type = Args.notNull(entry, "entry").getType();

    CertPublisher publisher;
    IdentifiedCertPublisher ret;
    try {
      if (manager.certPublisherFactoryRegister.canCreatePublisher(type)) {
        publisher = manager.certPublisherFactoryRegister.newPublisher(type);
      } else {
        throw new CaMgmtException("unsupported publisher type " + type);
      }

      ret = new IdentifiedCertPublisher(entry, publisher);
      ret.initialize(manager.getDataSourceMap());
      return ret;
    } catch (ObjectCreationException | CertPublisherException
             | RuntimeException ex) {
      String msg = "invalid configuration for the publisher "
          + entry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createPublisher

}
