/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.impl.store;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.impl.CaIdNameMap;
import org.xipki.ca.server.impl.CertRevInfoWithSerial;
import org.xipki.ca.server.impl.CertStatus;
import org.xipki.ca.server.impl.KnowCertResult;
import org.xipki.ca.server.impl.SerialWithId;
import org.xipki.ca.server.impl.UniqueIdGenerator;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.CertListInfo;
import org.xipki.ca.server.mgmt.api.CertListOrderBy;
import org.xipki.common.util.Base64;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertificateStore {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateStore.class);

    private final CertStoreQueryExecutor queryExecutor;

    public CertificateStore(DataSourceWrapper datasource, UniqueIdGenerator idGenerator)
            throws DataAccessException {
        ParamUtil.requireNonNull("datasource", datasource);
        this.queryExecutor = new CertStoreQueryExecutor(datasource, idGenerator);
    }

    public boolean addCertificate(X509CertificateInfo certInfo) {
        ParamUtil.requireNonNull("certInfo", certInfo);
        try {
            queryExecutor.addCert(certInfo.issuer(), certInfo.cert(),
                    certInfo.subjectPublicKey(), certInfo.profile(),
                    certInfo.requestor(), certInfo.user(), certInfo.reqType(),
                    certInfo.transactionId(), certInfo.requestedSubject());
        } catch (Exception ex) {
            LOG.error("could not save certificate {}: {}. Message: {}",
                    new Object[]{certInfo.cert().subject(),
                        Base64.encodeToString(certInfo.cert().encodedCert(), true),
                        ex.getMessage()});
            LOG.debug("error", ex);
            return false;
        }

        return true;
    }

    public void addToPublishQueue(NameId publisher, long certId, NameId ca)
            throws OperationException {
        try {
            queryExecutor.addToPublishQueue(publisher, certId, ca);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void removeFromPublishQueue(NameId publisher, long certId) throws OperationException {
        try {
            queryExecutor.removeFromPublishQueue(publisher, certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void clearPublishQueue(NameId ca, NameId publisher) throws OperationException {
        try {
            queryExecutor.clearPublishQueue(ca, publisher);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getMaxIdOfDeltaCrlCache(NameId ca) throws OperationException {
        try {
            return queryExecutor.getMaxIdOfDeltaCrlCache(ca);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void clearDeltaCrlCache(NameId ca, long maxId) throws OperationException {
        try {
            queryExecutor.clearDeltaCrlCache(ca, maxId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo revokeCertificate(NameId ca, BigInteger serialNumber,
            CertRevocationInfo revInfo, boolean force, boolean publishToDeltaCrlCache,
            CaIdNameMap idNameMap) throws OperationException {
        try {
            X509CertWithRevocationInfo revokedCert = queryExecutor.revokeCert(ca, serialNumber,
                    revInfo, force, publishToDeltaCrlCache, idNameMap);
            if (revokedCert == null) {
                LOG.info("could not revoke non-existing certificate CA={}, serialNumber={}",
                    ca.name(), LogUtil.formatCsn(serialNumber));
            } else {
                LOG.info("revoked certificate CA={}, serialNumber={}", ca.name(),
                        LogUtil.formatCsn(serialNumber));
            }

            return revokedCert;
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo revokeSuspendedCert(NameId ca, BigInteger serialNumber,
            CrlReason reason, boolean publishToDeltaCrlCache, CaIdNameMap idNameMap)
            throws OperationException {
        try {
            X509CertWithRevocationInfo revokedCert = queryExecutor.revokeSuspendedCert(ca,
                    serialNumber, reason, publishToDeltaCrlCache, idNameMap);
            if (revokedCert == null) {
                LOG.info("could not revoke non-existing certificate CA={}, serialNumber={}",
                    ca.name(), LogUtil.formatCsn(serialNumber));
            } else {
                LOG.info("revoked suspended certificate CA={}, serialNumber={}",
                        ca.name(), LogUtil.formatCsn(serialNumber));
            }

            return revokedCert;
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithDbId unrevokeCertificate(NameId ca, BigInteger serialNumber, boolean force,
            boolean publishToDeltaCrlCache, CaIdNameMap idNameMap) throws OperationException {
        try {
            X509CertWithDbId unrevokedCert = queryExecutor.unrevokeCert(ca, serialNumber, force,
                    publishToDeltaCrlCache, idNameMap);
            if (unrevokedCert == null) {
                LOG.info("could not unrevoke non-existing certificate CA={}, serialNumber={}",
                    ca.name(), LogUtil.formatCsn(serialNumber));
            } else {
                LOG.info("unrevoked certificate CA={}, serialNumber={}", ca.name(),
                        LogUtil.formatCsn(serialNumber));
            }

            return unrevokedCert;
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    X509CertWithDbId getCert(NameId ca, BigInteger serialNumber, CaIdNameMap idNameMap)
            throws OperationException {
        try {
            return queryExecutor.getCert(ca, serialNumber, idNameMap);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void removeCertificate(NameId ca, BigInteger serialNumber) throws OperationException {
        try {
            queryExecutor.removeCertificate(ca, serialNumber);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean addCrl(NameId ca, X509CRL crl) {
        try {
            queryExecutor.addCrl(ca, crl);
            return true;
        } catch (Exception ex) {
            LOG.error("could not add CRL ca={}, thisUpdate={}: {}, ",
                ca.name(), crl.getThisUpdate(), ex.getMessage());
            LOG.debug("Exception", ex);
            return false;
        }
    }

    public boolean hasCrl(NameId ca) throws OperationException {
        try {
            return queryExecutor.hasCrl(ca);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getMaxCrlNumber(NameId ca) throws OperationException {
        try {
            return queryExecutor.getMaxCrlNumber(ca);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getThisUpdateOfCurrentCrl(NameId ca) throws OperationException {
        try {
            return queryExecutor.getThisUpdateOfCurrentCrl(ca);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public byte[] getEncodedCrl(NameId ca, BigInteger crlNumber) {
        try {
            return queryExecutor.getEncodedCrl(ca, crlNumber);
        } catch (Exception ex) {
            LOG.error("could not get CRL ca={}: error message: {}", ca.name(), ex.getMessage());
            LOG.debug("Exception", ex);
            return null;
        }
    }

    public int cleanupCrls(NameId ca, int numCrls) {
        try {
            return queryExecutor.cleanupCrls(ca, numCrls);
        } catch (Exception ex) {
            LOG.error("could not cleanup CRLs ca={}: error message: {}", ca.name(),
                    ex.getMessage());
            LOG.debug("Exception", ex);
            return 0;
        }
    }

    public CertStatus getCertStatusForSubject(NameId ca, X500Principal subject) {
        try {
            return queryExecutor.getCertStatusForSubject(ca, subject);
        } catch (DataAccessException ex) {
            LOG.error("queryExecutor.getCertStatusForSubject. DataAccessException: {}",
                    ex.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", ex);
            return CertStatus.UNKNOWN;
        }
    }

    public CertStatus getCertStatusForSubject(NameId ca, X500Name subject) {
        try {
            return queryExecutor.getCertStatusForSubject(ca, subject);
        } catch (DataAccessException ex) {
            LogUtil.error(LOG, ex, "queryExecutor.getCertStatusForSubject");
            return CertStatus.UNKNOWN;
        }
    }

    /**
     * Returns the first serial number ascend sorted {@code numEntries} revoked certificates
     * which are not expired at {@code notExpiredAt} and the IDs are not less than {@code startId}.
     *
     * @param ca
     *          CA identifier
     * @param notExpiredAt
     *          Date at which the certificate is not expired.
     * @param startId
     *          The smallest id in the database ID column
     * @param numEntries
     *          Maximal entries in the returned list.
     * @param onlyCaCerts
     *          Indicates whether only certificates which can be used to issuer other certificates
     *          will be considered.
     * @param onlyUserCerts
     *          Indicates whether only end entity certificates will be considered.
     * @return list of revoked certificate meta info.
     * @throws OperationException
     *         if error occurs
     */
    public List<CertRevInfoWithSerial> getRevokedCerts(NameId ca, Date notExpiredAt, long startId,
            int numEntries, boolean onlyCaCerts, boolean onlyUserCerts) throws OperationException {
        try {
            return queryExecutor.getRevokedCertificates(ca, notExpiredAt, startId,
                    numEntries, onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<CertRevInfoWithSerial> getCertsForDeltaCrl(NameId ca, long startId, int numEntries,
            boolean onlyCaCerts, boolean onlyUserCerts) throws OperationException {
        try {
            return queryExecutor.getCertificatesForDeltaCrl(ca, startId, numEntries,
                    onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getCountOfCerts(NameId ca, boolean onlyRevoked) throws OperationException {
        try {
            return queryExecutor.getCountOfCerts(ca, onlyRevoked);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<SerialWithId> getCertSerials(NameId ca, long startId, int numEntries,
            boolean onlyRevoked) throws OperationException {
        try {
            return queryExecutor.getSerialNumbers(ca, startId, numEntries, onlyRevoked);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<SerialWithId> getCertSerials(NameId ca, Date notExpiredAt, long startId,
            int numEntries, boolean onlyRevoked, boolean onlyCaCerts, boolean onlyUserCerts)
            throws OperationException {
        try {
            return queryExecutor.getSerialNumbers(ca, notExpiredAt, startId, numEntries,
                    onlyRevoked, onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<BigInteger> getExpiredCertSerials(NameId ca, long expiredAt, int numEntries)
            throws OperationException {
        try {
            return queryExecutor.getExpiredSerialNumbers(ca, expiredAt, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<BigInteger> getSuspendedCertSerials(NameId ca, long latestLastUpdate,
            int numEntries) throws OperationException {
        try {
            return queryExecutor.getSuspendedCertSerials(ca, latestLastUpdate, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<Long> getPublishQueueEntries(NameId ca, NameId publisher, int numEntries)
            throws OperationException {
        try {
            return queryExecutor.getPublishQueueEntries(ca, publisher, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo getCertWithRevocationInfo(NameId ca,
            BigInteger serial, CaIdNameMap idNameMap) throws OperationException {
        try {
            return queryExecutor.getCertWithRevocationInfo(ca, serial, idNameMap);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForSerial(NameId ca, X509Cert caCert,
            BigInteger serial, CaIdNameMap idNameMap)
            throws OperationException, CertificateException {
        try {
            return queryExecutor.getCertificateInfo(ca, caCert, serial, idNameMap);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Integer getCertProfileForId(NameId ca, long id) throws OperationException {
        try {
            return queryExecutor.getCertProfileForCertId(ca, id);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Integer getCertProfileForSerial(NameId ca, BigInteger serial) throws OperationException {
        try {
            return queryExecutor.getCertProfileForSerial(ca, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<X509Certificate> getCertificate(X500Name subjectName, byte[] transactionId)
            throws OperationException {
        try {
            return queryExecutor.getCertificate(subjectName, transactionId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public byte[] getCertRequest(NameId ca, BigInteger serialNumber) throws OperationException {
        try {
            return queryExecutor.getCertRequest(ca, serialNumber);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<CertListInfo> listCertificates(NameId ca, X500Name subjectPattern, Date validFrom,
            Date validTo, CertListOrderBy orderBy, int numEntries) throws OperationException {
        try {
            return queryExecutor.listCertificates(ca, subjectPattern, validFrom, validTo,
                    orderBy, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public NameId authenticateUser(String user, byte[] password) throws OperationException {
        try {
            return queryExecutor.authenticateUser(user, password);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public NameId getUserIdent(int userId) throws OperationException {
        try {
            String name = queryExecutor.getUsername(userId);
            return (name == null) ? null : new NameId(userId, name);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public CaHasUserEntry getCaHasUser(NameId ca, NameId user) throws OperationException {
        try {
            return queryExecutor.getCaHasUser(ca, user);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public KnowCertResult knowsCertForSerial(NameId ca, BigInteger serial)
            throws OperationException {
        try {
            return queryExecutor.knowsCertForSerial(ca, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean isHealthy() {
        return queryExecutor.isHealthy();
    }

    public boolean isCertForSubjectIssued(NameId ca, long subjectFp) throws OperationException {
        try {
            return queryExecutor.isCertForSubjectIssued(ca, subjectFp);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean isCertForKeyIssued(NameId ca, long keyFp) throws OperationException {
        try {
            return queryExecutor.isCertForKeyIssued(ca, keyFp);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForId(NameId ca, X509Cert caCert,long certId,
            CaIdNameMap idNameMap) throws OperationException, CertificateException {
        try {
            return queryExecutor.getCertForId(ca, caCert, certId, idNameMap);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithDbId getCertForId(long certId) throws OperationException {
        try {
            return queryExecutor.getCertForId(certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public String getLatestSerialNumber(X500Name nameWithSerialNumber) throws OperationException {
        try {
            return queryExecutor.getLatestSerialNumber(nameWithSerialNumber);
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Long getNotBeforeOfFirstCertStartsWithCommonName(String commonName, NameId profile)
            throws OperationException {
        try {
            return queryExecutor.getNotBeforeOfFirstCertStartsWithCommonName(commonName, profile);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean containsCaCertificates(NameId ca) throws OperationException {
        try {
            return queryExecutor.containsCertificates(ca, false);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean containsEeCertificates(NameId ca) throws OperationException {
        try {
            return queryExecutor.containsCertificates(ca, true);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void deleteUnreferencedRequests() throws OperationException {
        try {
            queryExecutor.deleteUnreferencedRequests();
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long addRequest(byte[] request) throws OperationException {
        try {
            return queryExecutor.addRequest(request);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void addRequestCert(long requestId, long certId) throws OperationException {
        try {
            queryExecutor.addRequestCert(requestId, certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

}
