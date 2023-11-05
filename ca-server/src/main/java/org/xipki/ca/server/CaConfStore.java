// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.mgmt.CaProfileIdAliases;
import org.xipki.password.PasswordResolver;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.SecurityFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Execute the database queries to manage CA system.
 *
 * @author Lijun Liao (xipki)
 */
public interface CaConfStore {

  /**
   * Retrieve the system event.
   * @param eventName Event name
   * @return the System event, may be {@code null}.
   * @throws CaMgmtException
   *            If error occurs.
   */
  SystemEvent getSystemEvent(String eventName) throws CaMgmtException;

  void changeSystemEvent(SystemEvent systemEvent) throws CaMgmtException;

  Map<String, Integer> createCaAliases() throws CaMgmtException;

  CertprofileEntry createCertprofile(String name) throws CaMgmtException;

  PublisherEntry createPublisher(String name) throws CaMgmtException;

  Integer getRequestorId(String requestorName) throws CaMgmtException;

  RequestorEntry createRequestor(String name) throws CaMgmtException;

  SignerEntry createSigner(String name) throws CaMgmtException;

  KeypairGenEntry createKeypairGen(String name) throws CaMgmtException;

  CaInfo createCaInfo(String name, CertStore certstore) throws CaMgmtException;

  Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca) throws CaMgmtException;

  Set<CaProfileIdAliases> createCaHasProfiles(NameId ca) throws CaMgmtException;

  Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException;

  void addCa(CaEntry caEntry) throws CaMgmtException;

  void addCaAlias(String aliasName, NameId ca) throws CaMgmtException;

  void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException;

  void addCertprofileToCa(NameId profile, NameId ca, List<String> aliases) throws CaMgmtException;

  void addPublisherToCa(NameId publisher, NameId ca) throws CaMgmtException;

  void addRequestor(RequestorEntry dbEntry) throws CaMgmtException;

  NameId addEmbeddedRequestor(String requestorName) throws CaMgmtException;

  void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca) throws CaMgmtException;

  void addPublisher(PublisherEntry dbEntry) throws CaMgmtException;

  void changeCa(ChangeCaEntry changeCaEntry,
                       CaConfColumn currentCaConfColumn, SecurityFactory securityFactory)
      throws CaMgmtException;

  void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException;

  IdentifiedCertprofile changeCertprofile(
      NameId nameId, String type, String conf, CaManagerImpl certprofileManager)
      throws CaMgmtException;

  RequestorEntryWrapper changeRequestor(
      NameId nameId, String type, String conf, PasswordResolver passwordResolver)
      throws CaMgmtException;

  SignerEntryWrapper changeSigner(
      String name, String type, String conf, String base64Cert, CaManagerImpl signerManager)
      throws CaMgmtException;

  KeypairGenEntryWrapper changeKeypairGen(String name, String type, String conf, CaManagerImpl manager)
      throws CaMgmtException;

  IdentifiedCertPublisher changePublisher(String name, String type, String conf, CaManagerImpl publisherManager)
      throws CaMgmtException;

  void removeCaAlias(String aliasName) throws CaMgmtException;

  void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException;

  void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException;

  void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException;

  void removeDbSchema(String name) throws CaMgmtException;

  void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException;

  void addKeypairGen(KeypairGenEntry dbEntry) throws CaMgmtException;

  void addSigner(SignerEntry dbEntry) throws CaMgmtException;

  void unlockCa() throws CaMgmtException;

  void unrevokeCa(String caName) throws CaMgmtException;

  int getDbSchemaVersion();

  void addDbSchema(String name, String value) throws CaMgmtException;

  void changeDbSchema(String name, String value) throws CaMgmtException;

  Map<String, String> getDbSchemas() throws CaMgmtException;

  List<String> getCaNames() throws CaMgmtException;

  boolean deleteCa(String name) throws CaMgmtException;

  List<String>  getKeyPairGenNames() throws CaMgmtException;

  boolean deleteKeyPairGen(String name) throws CaMgmtException;

  List<String> getProfileNames() throws CaMgmtException;

  boolean deleteProfile(String name) throws CaMgmtException;

  List<String> getPublisherNames() throws CaMgmtException;

  boolean deletePublisher(String name) throws CaMgmtException;

  List<String> getRequestorNames() throws CaMgmtException;

  boolean deleteRequestor(String name) throws CaMgmtException;

  List<String> getSignerNames() throws CaMgmtException;

  boolean deleteSigner(String name) throws CaMgmtException;

}
