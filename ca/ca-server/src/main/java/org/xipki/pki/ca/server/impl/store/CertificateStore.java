/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.impl.store;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.CaIdNameMap;
import org.xipki.pki.ca.server.impl.CertRevInfoWithSerial;
import org.xipki.pki.ca.server.impl.CertStatus;
import org.xipki.pki.ca.server.impl.KnowCertResult;
import org.xipki.pki.ca.server.impl.SerialWithId;
import org.xipki.pki.ca.server.impl.UniqueIdGenerator;
import org.xipki.pki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CertListInfo;
import org.xipki.pki.ca.server.mgmt.api.CertListOrderBy;
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

    public CertificateStore(final DataSourceWrapper datasource,
            final UniqueIdGenerator idGenerator) throws DataAccessException {
        ParamUtil.requireNonNull("datasource", datasource);
        this.queryExecutor = new CertStoreQueryExecutor(datasource, idGenerator);
    }

    public boolean addCertificate(final X509CertificateInfo certInfo) {
        ParamUtil.requireNonNull("certInfo", certInfo);
        try {
            queryExecutor.addCert(certInfo.issuer(), certInfo.cert(),
                    certInfo.subjectPublicKey(), certInfo.profile(),
                    certInfo.requestor(), certInfo.user(), certInfo.reqType(),
                    certInfo.transactionId(), certInfo.requestedSubject());
        } catch (Exception ex) {
            LOG.error("could not save certificate {}: {}. Message: {}",
                    new Object[]{certInfo.cert().subject(),
                        Base64.toBase64String(certInfo.cert().encodedCert()),
                        ex.getMessage()});
            LOG.debug("error", ex);
            return false;
        }

        return true;
    }

    public void addToPublishQueue(final NameId publisher, final long certId,
            final NameId ca) throws OperationException {
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

    public void removeFromPublishQueue(final NameId publisher, final long certId)
            throws OperationException {
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

    public void clearPublishQueue(final NameId ca, final NameId publisher)
            throws OperationException {
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

    public long getMaxIdOfDeltaCrlCache(final NameId ca) throws OperationException {
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

    public void clearDeltaCrlCache(final NameId ca, final long maxId)
            throws OperationException {
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

    public X509CertWithRevocationInfo revokeCertificate(final NameId ca,
            final BigInteger serialNumber, final CertRevocationInfo revInfo, final boolean force,
            final boolean publishToDeltaCrlCache, final CaIdNameMap idNameMap)
            throws OperationException {
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

    public X509CertWithRevocationInfo revokeSuspendedCert(final NameId ca,
            final BigInteger serialNumber, final CrlReason reason,
            final boolean publishToDeltaCrlCache, final CaIdNameMap idNameMap)
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

    public X509CertWithDbId unrevokeCertificate(final NameId ca,
            final BigInteger serialNumber, final boolean force,
            final boolean publishToDeltaCrlCache, final CaIdNameMap idNameMap)
            throws OperationException {
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

    X509CertWithDbId getCert(final NameId ca, final BigInteger serialNumber,
            final CaIdNameMap idNameMap) throws OperationException {
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

    public void removeCertificate(final NameId ca, final BigInteger serialNumber)
            throws OperationException {
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

    public boolean addCrl(final NameId ca, final X509CRL crl) {
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

    public boolean hasCrl(final NameId ca) throws OperationException {
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

    public long getMaxCrlNumber(final NameId ca) throws OperationException {
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

    public long getThisUpdateOfCurrentCrl(final NameId ca) throws OperationException {
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

    public byte[] getEncodedCrl(final NameId ca, final BigInteger crlNumber) {
        try {
            return queryExecutor.getEncodedCrl(ca, crlNumber);
        } catch (Exception ex) {
            LOG.error("could not get CRL ca={}: error message: {}", ca.name(), ex.getMessage());
            LOG.debug("Exception", ex);
            return null;
        }
    }

    public int cleanupCrls(final NameId ca, final int numCrls) {
        try {
            return queryExecutor.cleanupCrls(ca, numCrls);
        } catch (Exception ex) {
            LOG.error("could not cleanup CRLs ca={}: error message: {}", ca.name(),
                    ex.getMessage());
            LOG.debug("Exception", ex);
            return 0;
        }
    }

    public CertStatus getCertStatusForSubject(final NameId ca,
            final X500Principal subject) {
        try {
            return queryExecutor.getCertStatusForSubject(ca, subject);
        } catch (DataAccessException ex) {
            LOG.error("queryExecutor.getCertStatusForSubject. DataAccessException: {}",
                    ex.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", ex);
            return CertStatus.UNKNOWN;
        }
    }

    public CertStatus getCertStatusForSubject(final NameId ca, final X500Name subject) {
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
     */
    public List<CertRevInfoWithSerial> getRevokedCerts(final NameId ca,
            final Date notExpiredAt, final long startId, final int numEntries,
            final boolean onlyCaCerts, final boolean onlyUserCerts) throws OperationException {
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

    public List<CertRevInfoWithSerial> getCertsForDeltaCrl(final NameId ca,
            final long startId, final int numEntries, final boolean onlyCaCerts,
            final boolean onlyUserCerts) throws OperationException {
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

    public long getCountOfCerts(final NameId ca, final boolean onlyRevoked)
            throws OperationException {
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

    public List<SerialWithId> getCertSerials(final NameId ca, final long startId,
            final int numEntries, final boolean onlyRevoked) throws OperationException {
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

    public List<SerialWithId> getCertSerials(final NameId ca, final Date notExpiredAt,
            final long startId, final int numEntries, final boolean onlyRevoked,
            final boolean onlyCaCerts, final boolean onlyUserCerts) throws OperationException {
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

    public List<BigInteger> getExpiredCertSerials(final NameId ca, final long expiredAt,
            final int numEntries) throws OperationException {
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

    public List<BigInteger> getSuspendedCertSerials(final NameId ca,
            final long latestLastUpdate, final int numEntries) throws OperationException {
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

    public List<Long> getPublishQueueEntries(final NameId ca,
            final NameId publisher, final int numEntries) throws OperationException {
        try {
            return queryExecutor.getPublishQueueEntries(ca, publisher, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo getCertWithRevocationInfo(final NameId ca,
            final BigInteger serial, final CaIdNameMap idNameMap) throws OperationException {
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

    public X509CertificateInfo getCertificateInfoForSerial(final NameId ca,
            final X509Cert caCert, final BigInteger serial, final CaIdNameMap idNameMap)
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

    public Integer getCertProfileForId(final NameId ca, final long id)
            throws OperationException {
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

    public Integer getCertProfileForSerial(final NameId ca, final BigInteger serial)
            throws OperationException {
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

    public List<X509Certificate> getCertificate(final X500Name subjectName,
            final byte[] transactionId) throws OperationException {
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

    public byte[] getCertRequest(final NameId ca, final BigInteger serialNumber)
            throws OperationException {
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

    public List<CertListInfo> listCertificates(final NameId ca,
            final X500Name subjectPattern,
            final Date validFrom, final Date validTo, final CertListOrderBy orderBy,
            final int numEntries) throws OperationException {
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

    public NameId authenticateUser(final String user, final byte[] password)
            throws OperationException {
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

    public NameId getUserIdent(final int userId)
            throws OperationException {
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

    public CaHasUserEntry getCaHasUser(final NameId ca, final NameId user)
            throws OperationException {
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

    public KnowCertResult knowsCertForSerial(final NameId ca, final BigInteger serial)
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

    public boolean isCertForSubjectIssued(final NameId ca, final long subjectFp)
            throws OperationException {
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

    public boolean isCertForKeyIssued(final NameId ca, final long keyFp)
            throws OperationException {
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

    public X509CertificateInfo getCertificateInfoForId(final NameId ca,
            final X509Cert caCert,final long certId, final CaIdNameMap idNameMap)
            throws OperationException, CertificateException {
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

    public X509CertWithDbId getCertForId(final long certId) throws OperationException {
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

    public String getLatestSerialNumber(final X500Name nameWithSerialNumber)
            throws OperationException {
        try {
            return queryExecutor.getLatestSerialNumber(nameWithSerialNumber);
        } catch (RuntimeException ex) {
            LOG.debug("RuntimeException", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Long getNotBeforeOfFirstCertStartsWithCommonName(final String commonName,
            final NameId profile) throws OperationException {
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

    public boolean containsCaCertificates(final NameId ca) throws OperationException {
        try {
            return queryExecutor.containsCertificates(ca, false);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean containsEeCertificates(final NameId ca) throws OperationException {
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
