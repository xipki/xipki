// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.io.*;
import java.math.BigInteger;
import java.time.Instant;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.*;

/**
 * Narrow XiPKI 7.0 management surface consumed by Console.
 *
 * @author palos
 */
public interface CaManager {
  CaSystemStatus getCaSystemStatus() throws CaMgmtException;

  void unlockCa() throws CaMgmtException;

  void notifyCaChange() throws CaMgmtException;

  void addDbSchema(String name, String value) throws CaMgmtException;

  void changeDbSchema(String name, String value) throws CaMgmtException;

  void removeDbSchema(String name) throws CaMgmtException;

  Map<String, String> getDbSchemas() throws CaMgmtException;

  void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException;

  void removeCa(String caName) throws CaMgmtException;

  void restartCa(String caName) throws CaMgmtException;

  void restartCaSystem() throws CaMgmtException;

  void addCaAlias(String aliasName, String caName) throws CaMgmtException;

  void removeCaAlias(String aliasName) throws CaMgmtException;

  Set<String> getAliasesForCa(String caName) throws CaMgmtException;

  String getCaNameForAlias(String aliasName) throws CaMgmtException;

  Set<String> getCaAliasNames() throws CaMgmtException;

  Set<String> getCertprofileNames() throws CaMgmtException;

  Set<String> getKeypairGenNames() throws CaMgmtException;

  Set<String> getPublisherNames() throws CaMgmtException;

  Set<String> getRequestorNames() throws CaMgmtException;

  Set<String> getSignerNames() throws CaMgmtException;

  Set<String> getCaNames() throws CaMgmtException;

  Set<String> getSuccessfulCaNames() throws CaMgmtException;

  Set<String> getFailedCaNames() throws CaMgmtException;

  Set<String> getInactiveCaNames() throws CaMgmtException;

  void addCa(CaEntry caEntry) throws CaMgmtException;

  CaEntry getCa(String caName) throws CaMgmtException;

  void changeCa(ChangeCaEntry changeCaEntry) throws CaMgmtException;

  void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException;

  void addCertprofileToCa(String profileNameAliases, String caName) throws CaMgmtException;

  void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException;

  void addPublisherToCa(String publisherName, String caName) throws CaMgmtException;

  Set<CaProfileEntry> getCertprofilesForCa(String caName) throws CaMgmtException;

  Set<CaHasRequestorEntry> getRequestorsForCa(String caName) throws CaMgmtException;

  RequestorEntry getRequestor(String name) throws CaMgmtException;

  void addRequestor(RequestorEntry requestorEntry) throws CaMgmtException;

  void removeRequestor(String requestorName) throws CaMgmtException;

  void changeRequestor(String name, String type, String conf) throws CaMgmtException;

  void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException;

  void addRequestorToCa(CaHasRequestorEntry requestor, String caName) throws CaMgmtException;

  CertprofileEntry getCertprofile(String profileName) throws CaMgmtException;

  void removeCertprofile(String profileName) throws CaMgmtException;

  void changeCertprofile(String name, String type, String conf) throws CaMgmtException;

  void addCertprofile(CertprofileEntry certprofileEntry) throws CaMgmtException;

  KeypairGenEntry getKeypairGen(String name) throws CaMgmtException;

  void removeKeypairGen(String name) throws CaMgmtException;

  void changeKeypairGen(String name, String type, String conf) throws CaMgmtException;

  void addKeypairGen(KeypairGenEntry keypairGenEntry) throws CaMgmtException;

  void addSigner(SignerEntry signerEntry) throws CaMgmtException;

  void removeSigner(String name) throws CaMgmtException;

  SignerEntry getSigner(String name) throws CaMgmtException;

  void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException;

  void addPublisher(PublisherEntry entry) throws CaMgmtException;

  Set<String> getPublisherNamesForCa(String caName) throws CaMgmtException;

  PublisherEntry getPublisher(String publisherName) throws CaMgmtException;

  void removePublisher(String publisherName) throws CaMgmtException;

  void changePublisher(String name, String type, String conf) throws CaMgmtException;

  void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException;

  void unrevokeCa(String caName) throws CaMgmtException;

  void revokeCertificate(
      String caName, BigInteger serialNumber, CrlReason reason, Instant invalidityTime)
      throws CaMgmtException;

  void unsuspendCertificate(String caName, BigInteger serialNumber) throws CaMgmtException;

  void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException;

  X509Cert generateCertificate(
      String caName, String profileName, byte[] encodedCsr, Instant notBefore, Instant notAfter)
      throws CaMgmtException;

  KeyCertBytesPair generateKeyCert(
      String caName, String profileName, String subject, Instant notBefore, Instant notAfter)
      throws CaMgmtException;

  X509Cert generateCrossCertificate(
      String caName,
      String profileName,
      byte[] encodedCsr,
      byte[] encodedTargetCert,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException;

  X509Cert generateRootCa(
      CaEntry caEntry,
      String certprofileName,
      String subject,
      String serialNumber,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException;

  X509Crl generateCrlOnDemand(String caName) throws CaMgmtException;

  X509Crl getCrl(String caName, long crlNumber) throws CaMgmtException;

  X509Crl getCurrentCrl(String caName) throws CaMgmtException;

  List<X509Cert> getCaCerts(String caName) throws CaMgmtException;

  CertWithRevocationInfo getCert(String caName, BigInteger serialNumber) throws CaMgmtException;

  void loadConfAndClose(InputStream zippedConfStream) throws CaMgmtException, IOException;

  InputStream exportConf(List<String> caNames) throws CaMgmtException, IOException;

  List<CertListInfo> listCertificates(
      String caName,
      X500Principal subjectPattern,
      Instant validFrom,
      Instant validTo,
      CertListOrderBy orderBy,
      int numEntries)
      throws CaMgmtException;

  Set<String> getSupportedSignerTypes() throws CaMgmtException;

  Set<String> getSupportedCertprofileTypes() throws CaMgmtException;

  Set<String> getSupportedPublisherTypes() throws CaMgmtException;

  String getTokenInfoP11(String moduleName, Integer slotIndex, boolean verbose)
      throws CaMgmtException;
}
