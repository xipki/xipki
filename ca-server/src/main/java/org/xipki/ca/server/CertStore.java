// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.X509Crl;
import org.xipki.security.exception.OperationException;
import org.xipki.util.datasource.DataAccessException;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.time.Instant;
import java.util.List;

/**
 * CA cert store.
 *
 * @author Lijun Liao (xipki)
 */

public interface CertStore {

  enum CertStatus {

    UNKNOWN,
    REVOKED,
    GOOD

  } // class CertStatus

  class SerialWithId {

    private final long id;

    private final BigInteger serial;

    public SerialWithId(long id, BigInteger serial) {
      this.id = id;
      this.serial = serial;
    }

    public BigInteger serial() {
      return serial;
    }

    public long id() {
      return id;
    }

  }

  void removeCa(String name) throws CaMgmtException;

  void removeCertProfile(String name) throws CaMgmtException;

  void removeRequestor(String name) throws CaMgmtException;

  void addCertProfile(NameId ident) throws CaMgmtException;

  void addRequestor(NameId ident) throws CaMgmtException;

  void addCa(NameId ident, X509Cert caCert, CertRevocationInfo caRevInfo)
      throws CaMgmtException;

  void revokeCa(String caName, CertRevocationInfo revocationInfo)
      throws CaMgmtException;

  void unrevokeCa(String caName) throws CaMgmtException;

  boolean addCert(CertificateInfo certInfo, boolean saveKeypair);

  long getMaxFullCrlNumber(NameId ca) throws OperationException;

  long getMaxCrlNumber(NameId ca) throws OperationException;

  long getThisUpdateOfCurrentCrl(NameId ca, boolean deltaCrl)
      throws OperationException;

  void addCrl(NameId ca, X509Crl crl) throws OperationException, CRLException;

  CertWithRevocationInfo revokeCert(
      NameId ca, BigInteger serialNumber, CertRevocationInfo revInfo,
      boolean force, CaIdNameMap idNameMap)
      throws OperationException;

  CertWithRevocationInfo revokeSuspendedCert(
      NameId ca, SerialWithId serialNumber, CrlReason reason,
      CaIdNameMap idNameMap) throws OperationException;

  CertWithDbId unsuspendCert(NameId ca, BigInteger serialNumber,
                             boolean force, CaIdNameMap idNamMap)
      throws OperationException;

  void removeCert(long id) throws OperationException;

  long getCountOfCerts(NameId ca, boolean onlyRevoked)
      throws OperationException;

  long getCountOfCerts(long notBeforeSince) throws OperationException;

  List<SerialWithId> getSerialNumbers(
      NameId ca,  long startId, int numEntries, boolean onlyRevoked)
      throws OperationException;

  List<SerialWithId> getExpiredUnrevokedSerialNumbers(
      NameId ca, long expiredAt, int numEntries)
      throws OperationException;

  List<SerialWithId> getSuspendedCertSerials(
      NameId ca, Instant latestLastUpdate, int numEntries)
      throws OperationException;

  byte[] getEncodedCrl(NameId ca, BigInteger crlNumber)
      throws OperationException;

  int cleanupCrls(NameId ca, int numCrls) throws OperationException;

  CertificateInfo getCertForId(NameId ca, X509Cert caCert,
                               long certId, CaIdNameMap idNameMap)
      throws OperationException;

  CertWithRevocationInfo getCertWithRevocationInfo(
      long certId, CaIdNameMap idNameMap)
      throws OperationException;

  CertWithRevocationInfo getCertWithRevocationInfo(
      int caId, BigInteger serial, CaIdNameMap idNameMap)
      throws OperationException;

  CertWithRevocationInfo getCertWithRevocationInfoBySubject(
      int caId, X500Name subject, byte[] san, CaIdNameMap idNameMap)
      throws OperationException;

  long getCertId(NameId ca, BigInteger serial) throws OperationException;

  CertificateInfo getCertInfo(NameId ca, X509Cert caCert,
                              BigInteger serial, CaIdNameMap idNameMap)
      throws OperationException;

  /**
   * Get certificate for given subject and transactionId.
   *
   * @param subjectName Subject of Certificate or requested Subject.
   * @param transactionId the transactionId
   * @return certificate for given subject and transactionId.
   * @throws OperationException
   *         If error occurs.
   */
  X509Cert getCert(X500Name subjectName, String transactionId)
      throws OperationException;

  List<CertListInfo> listCerts(
      NameId ca, X500Name subjectPattern, Instant validFrom,
      Instant validTo, CertListOrderBy orderBy, int numEntries)
      throws OperationException;

  List<CertRevInfoWithSerial> getRevokedCerts(
      NameId ca, Instant notExpiredAt, long startId, int numEntries)
      throws OperationException;

  List<CertRevInfoWithSerial> getCertsForDeltaCrl(
      NameId ca, BigInteger baseCrlNumber, Instant notExpiredAt)
      throws OperationException;

  CertStatus getCertStatusForSubject(NameId ca, X500Name subject)
      throws OperationException;

  boolean isHealthy();

  void updateDbInfo() throws DataAccessException, CaMgmtException;

}
