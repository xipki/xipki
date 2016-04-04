/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.X509Cert;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.CertRevInfoWithSerial;
import org.xipki.pki.ca.server.impl.CertStatus;
import org.xipki.pki.ca.server.impl.KnowCertResult;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertificateStore {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateStore.class);

    private final CertStoreQueryExecutor queryExecutor;

    public CertificateStore(
            final DataSourceWrapper datasource)
    throws DataAccessException {
        ParamUtil.requireNonNull("datasource", datasource);
        this.queryExecutor = new CertStoreQueryExecutor(datasource);
    }

    public boolean addCertificate(
            final X509CertificateInfo certInfo) {
        ParamUtil.requireNonNull("certInfo", certInfo);
        try {
            queryExecutor.addCert(certInfo.getIssuerCert(),
                    certInfo.getCert(),
                    certInfo.getSubjectPublicKey(),
                    certInfo.getProfileName(),
                    certInfo.getRequestor(),
                    certInfo.getUser(),
                    certInfo.getReqType(),
                    certInfo.getTransactionId(),
                    certInfo.getRequestedSubject());
        } catch (Exception ex) {
            LOG.error("could not save certificate {}: {}. Message: {}",
                    new Object[]{certInfo.getCert().getSubject(),
                        Base64.toBase64String(certInfo.getCert().getEncodedCert()),
                        ex.getMessage()});
            LOG.debug("error", ex);
            return false;
        }

        return true;
    }

    public void addToPublishQueue(
            final String publisherName,
            final int certId,
            final X509Cert caCert)
    throws OperationException {
        try {
            queryExecutor.addToPublishQueue(publisherName, certId, caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void removeFromPublishQueue(
            final String publisherName,
            final int certId)
    throws OperationException {
        try {
            queryExecutor.removeFromPublishQueue(publisherName, certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void clearPublishQueue(
            final X509Cert caCert,
            final String publisherName)
    throws OperationException {
        try {
            queryExecutor.clearPublishQueue(caCert, publisherName);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getMaxIdOfDeltaCrlCache(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.getMaxIdOfDeltaCrlCache(caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void clearDeltaCrlCache(
            final X509Cert caCert,
            final long maxId)
    throws OperationException {
        try {
            queryExecutor.clearDeltaCrlCache(caCert, maxId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo revokeCertificate(
            final X509Cert caCert,
            final BigInteger serialNumber,
            final CertRevocationInfo revInfo,
            final boolean force,
            final boolean publishToDeltaCrlCache)
    throws OperationException {
        try {
            X509CertWithRevocationInfo revokedCert = queryExecutor.revokeCert(
                    caCert, serialNumber, revInfo, force, publishToDeltaCrlCache);
            if (revokedCert == null) {
                LOG.info("could not revoke non-existing certificate issuer='{}', serialNumber={}",
                    caCert.getSubject(), serialNumber);
            } else {
                LOG.info("revoked certificate issuer='{}', serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }

            return revokedCert;
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithDbId unrevokeCertificate(
            final X509Cert caCert,
            final BigInteger serialNumber,
            final boolean force,
            final boolean publishToDeltaCrlCache)
    throws OperationException {
        try {
            X509CertWithDbId unrevokedCert = queryExecutor.unrevokeCert(
                    caCert, serialNumber, force, publishToDeltaCrlCache);
            if (unrevokedCert == null) {
                LOG.info("could not unrevoke non-existing certificate issuer='{}', serialNumber={}",
                    caCert.getSubject(), serialNumber);
            } else {
                LOG.info("unrevoked certificate issuer='{}', serialNumber={}",
                        caCert.getSubject(), serialNumber);
            }

            return unrevokedCert;
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    X509CertWithDbId getCert(
            final X509Cert caCert,
            final BigInteger serialNumber)
    throws OperationException {
        try {
            return queryExecutor.getCert(caCert, serialNumber);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void removeCertificate(
            final X509Cert caCert,
            final BigInteger serialNumber)
    throws OperationException {
        try {
            queryExecutor.removeCertificate(caCert, serialNumber);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean addCrl(
            final X509Cert caCert,
            final X509CRL crl) {
        try {
            queryExecutor.addCrl(caCert, crl);
            return true;
        } catch (Exception ex) {
            LOG.error("could not add CRL ca={}, thisUpdate={}: {}, ",
                new Object[]{caCert.getSubject(),
                    crl.getThisUpdate(), ex.getMessage()});
            LOG.debug("Exception", ex);
            return false;
        }
    }

    public boolean hasCrl(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.hasCrl(caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public int getMaxCrlNumber(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.getMaxCrlNumber(caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long getThisUpdateOfCurrentCrl(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.getThisUpdateOfCurrentCrl(caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public byte[] getEncodedCrl(
            final X509Cert caCert,
            final BigInteger crlNumber) {
        try {
            return queryExecutor.getEncodedCrl(caCert, crlNumber);
        } catch (Exception ex) {
            LOG.error("could not get CRL ca={}: error message: {}",
                    caCert.getSubject(),
                    ex.getMessage());
            LOG.debug("Exception", ex);
            return null;
        }
    }

    public int cleanupCrls(
            final X509Cert caCert,
            final int numCrls) {
        try {
            return queryExecutor.cleanupCrls(caCert, numCrls);
        } catch (Exception ex) {
            LOG.error("could not cleanup CRLs ca={}: error message: {}",
                    caCert.getSubject(),
                    ex.getMessage());
            LOG.debug("Exception", ex);
            return 0;
        }
    }

    public CertStatus getCertStatusForSubject(
            final X509Cert caCert,
            final X500Principal subject) {
        try {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (DataAccessException ex) {
            LOG.error("queryExecutor.getCertStatusForSubject. DataAccessException: {}",
                    ex.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", ex);
            return CertStatus.Unknown;
        }
    }

    public CertStatus getCertStatusForSubject(
            final X509Cert caCert,
            final X500Name subject) {
        try {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (DataAccessException ex) {
            final String message = "queryExecutor.getCertStatusForSubject";
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);
            return CertStatus.Unknown;
        }
    }

    /**
     * Returns the first serial number ascend sorted {@code numEntries} revoked certificates
     * which are not expired at {@code notExpiredAt} and their serial numbers are not less than
     * {@code startSerial}.
     */
    public List<CertRevInfoWithSerial> getRevokedCerts(
            final X509Cert caCert,
            final Date notExpiredAt,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyCaCerts,
            final boolean onlyUserCerts)
    throws OperationException {
        try {
            return queryExecutor.getRevokedCertificates(caCert, notExpiredAt, startSerial,
                    numEntries, onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<CertRevInfoWithSerial> getCertsForDeltaCrl(
            final X509Cert caCert,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyCaCerts,
            final boolean onlyUserCerts)
    throws OperationException {
        try {
            return queryExecutor.getCertificatesForDeltaCrl(caCert, startSerial, numEntries,
                    onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<BigInteger> getCertSerials(
            final X509Cert caCert,
            final Date notExpiredAt,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyRevoked,
            final boolean onlyCaCerts,
            final boolean onlyUserCerts)
    throws OperationException {
        try {
            return queryExecutor.getSerialNumbers(caCert, notExpiredAt, startSerial,
                    numEntries, onlyRevoked,
                    onlyCaCerts, onlyUserCerts);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<BigInteger> getExpiredCertSerials(
            final X509Cert caCert,
            final long expiredAt,
            final int numEntries)
    throws OperationException {
        try {
            return queryExecutor.getExpiredSerialNumbers(caCert, expiredAt, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<Integer> getPublishQueueEntries(
            final X509Cert caCert,
            final String publisherName,
            final int numEntries)
    throws OperationException {
        try {
            return queryExecutor.getPublishQueueEntries(caCert, publisherName, numEntries);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithRevocationInfo getCertWithRevocationInfo(
            final X509Cert caCert,
            final BigInteger serial)
    throws OperationException {
        try {
            return queryExecutor.getCertWithRevocationInfo(caCert, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForSerial(
            final X509Cert caCert,
            final BigInteger serial)
    throws OperationException, CertificateException {
        try {
            return queryExecutor.getCertificateInfo(caCert, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public String getCertProfileForSerial(
            final X509Cert caCert,
            final BigInteger serial)
    throws OperationException {
        try {
            return queryExecutor.getCertProfileForSerial(caCert, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public List<X509Certificate> getCertificate(
            final X500Name subjectName,
            final byte[] transactionId)
    throws OperationException {
        try {
            return queryExecutor.getCertificate(subjectName, transactionId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean authenticateUser(
            final String user,
            final byte[] password)
    throws OperationException {
        try {
            return queryExecutor.authenticateUser(user, password);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public String getCnRegexForUser(
            final String user)
    throws OperationException {
        try {
            return queryExecutor.getCnRegexForUser(user);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public KnowCertResult knowsCertForSerial(
            final X509Cert caCert,
            final BigInteger serial)
    throws OperationException {
        try {
            return queryExecutor.knowsCertForSerial(caCert, serial);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Long getGreatestSerialNumber(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.getGreatestSerialNumber(caCert);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean isHealthy() {
        return queryExecutor.isHealthy();
    }

    public boolean isCertForSubjectIssued(
            final X509Cert caCert,
            final long subjectFp)
    throws OperationException {
        try {
            return queryExecutor.isCertForSubjectIssued(caCert, subjectFp);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean isCertForKeyIssued(
            final X509Cert caCert,
            final long keyFp)
    throws OperationException {
        try {
            return queryExecutor.isCertForKeyIssued(caCert, keyFp);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForId(
            final X509Cert caCert,
            final int certId)
    throws OperationException, CertificateException {
        try {
            return queryExecutor.getCertForId(caCert, certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public X509CertWithDbId getCertForId(
            final int certId)
    throws OperationException {
        try {
            return queryExecutor.getCertForId(certId);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public String getLatestSerialNumber(
            final X500Name nameWithSerialNumber)
    throws OperationException {
        try {
            return queryExecutor.getLatestSerialNumber(nameWithSerialNumber);
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public Long getNotBeforeOfFirstCertStartsWithCommonName(
            final String commonName,
            final String profileName)
    throws OperationException {
        try {
            return queryExecutor.getNotBeforeOfFirstCertStartsWithCommonName(commonName,
                    profileName);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean containsCaCertificates(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.containsCertificates(caCert, false);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean containsUserCertificates(
            final X509Cert caCert)
    throws OperationException {
        try {
            return queryExecutor.containsCertificates(caCert, true);
        } catch (DataAccessException ex) {
            LOG.debug("DataAccessException", ex);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public long nextSerial(
            final X509Cert caCert,
            final String seqName)
    throws OperationException {
        try {
            return queryExecutor.nextSerial(caCert, seqName);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void commitNextSerialIfLess(
            final String caName,
            final long nextSerial)
    throws OperationException {
        try {
            queryExecutor.commitNextSerialIfLess(caName, nextSerial);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void markMaxSerial(
            final X509Cert caCert,
            final String seqName)
    throws OperationException {
        try {
            queryExecutor.markMaxSerial(caCert, seqName);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void commitNextCrlNo(
            final String caName,
            final int nextCrlNo)
    throws OperationException {
        try {
            queryExecutor.commitNextCrlNoIfLess(caName, nextCrlNo);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void addCa(
            final X509Cert caCert)
    throws OperationException {
        try {
            queryExecutor.addCa(caCert);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void addRequestorName(
            final String name)
    throws OperationException {
        try {
            queryExecutor.addRequestorName(name);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void addPublisherName(
            final String name)
    throws OperationException {
        try {
            queryExecutor.addPublisherName(name);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void addCertprofileName(
            final String name)
    throws OperationException {
        try {
            queryExecutor.addCertprofileName(name);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public boolean addCertInProcess(
            final long fpKey,
            final long fpSubject)
    throws OperationException {
        try {
            return queryExecutor.addCertInProcess(fpKey, fpSubject);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void delteCertInProcess(
            final long fpKey,
            final long fpSubject)
    throws OperationException {
        try {
            queryExecutor.deleteCertInProcess(fpKey, fpSubject);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public void deleteCertsInProcessOlderThan(
            final Date time)
    throws OperationException {
        try {
            queryExecutor.deleteCertsInProcessOlderThan(time);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

}
