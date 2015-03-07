/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.impl.store;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.X509CertWithDBCertId;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.CertRevocationInfoWithSerial;
import org.xipki.ca.server.impl.CertStatus;
import org.xipki.ca.server.impl.SubjectKeyProfileBundle;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

public class CertificateStore
{
    private static final Logger LOG = LoggerFactory.getLogger(CertificateStore.class);
    private final CertStoreQueryExecutor queryExecutor;

    public CertificateStore(DataSourceWrapper dataSource)
    throws DataAccessException
    {
        ParamChecker.assertNotNull("dataSource", dataSource);

        this.queryExecutor = new CertStoreQueryExecutor(dataSource);
    }

    public boolean addCertificate(X509CertificateInfo certInfo)
    {
        try
        {
            queryExecutor.addCert(certInfo.getIssuerCert(),
                    certInfo.getCert(),
                    certInfo.getSubjectPublicKey(),
                    certInfo.getProfileName(),
                    certInfo.getRequestor(),
                    certInfo.getUser());
        } catch (Exception e)
        {
            LOG.error("Could not save certificate {}: {}. Message: {}",
                    new Object[]{certInfo.getCert().getSubject(),
                        Base64.toBase64String(certInfo.getCert().getEncodedCert()),
                        e.getMessage()});
            LOG.debug("error", e);
            return false;
        }

        return true;
    }

    public void addToPublishQueue(String publisherName, int certId, X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            queryExecutor.addToPublishQueue(publisherName, certId, caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void removeFromPublishQueue(String publisherName, int certId)
    throws OperationException
    {
        try
        {
            queryExecutor.removeFromPublishQueue(publisherName, certId);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void clearPublishQueue(X509CertWithDBCertId caCert, String publisherName)
    throws OperationException
    {
        try
        {
            queryExecutor.clearPublishQueue(caCert, publisherName);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public long getMaxIdOfDeltaCRLCache(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.getMaxIdOfDeltaCRLCache(caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void clearDeltaCRLCache(X509CertWithDBCertId caCert, long maxId)
    throws OperationException
    {
        try
        {
            queryExecutor.clearDeltaCRLCache(caCert, maxId);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertWithRevocationInfo revokeCertificate(X509CertWithDBCertId caCert,
            BigInteger serialNumber, CertRevocationInfo revInfo, boolean force, boolean publishToDeltaCRLCache)
    throws OperationException
    {
        try
        {
            X509CertWithRevocationInfo revokedCert = queryExecutor.revokeCert(
                    caCert, serialNumber, revInfo, force, publishToDeltaCRLCache);
            if(revokedCert == null)
            {
                LOG.info("Could not revoke non-existing certificate issuer='{}', serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("revoked certificate issuer='{}', serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return revokedCert;
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertWithDBCertId unrevokeCertificate(X509CertWithDBCertId caCert,
            BigInteger serialNumber, boolean force, boolean publishToDeltaCRLCache)
    throws OperationException
    {
        try
        {
            X509CertWithDBCertId unrevokedCert = queryExecutor.unrevokeCert(
                    caCert, serialNumber, force, publishToDeltaCRLCache);
            if(unrevokedCert == null)
            {
                LOG.info("Could not unrevoke non-existing certificate issuer='{}', serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("unrevoked certificate issuer='{}', serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return unrevokedCert;
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    X509CertWithDBCertId getCert(X509CertWithDBCertId caCert, BigInteger serialNumber)
    throws OperationException
    {
        try
        {
            return queryExecutor.getCert(caCert, serialNumber);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void removeCertificate(X509CertWithDBCertId caCert,
            BigInteger serialNumber)
    throws OperationException
    {
        try
        {
            queryExecutor.removeCertificate(caCert, serialNumber);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean addCRL(X509CertWithDBCertId caCert, X509CRL crl)
    {
        try
        {
            queryExecutor.addCRL(caCert, crl);
            return true;
        } catch (Exception e)
        {
            LOG.error("Could not add CRL ca={}, thisUpdate={}: {}, ",
                new Object[]{caCert.getSubject(),
                    crl.getThisUpdate(), e.getMessage()});
            LOG.debug("Exception", e);
            return false;
        }
    }

    public boolean hasCRL(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.hasCRL(caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public int getMaxCRLNumber(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.getMaxCrlNumber(caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public long getThisUpdateOfCurrentCRL(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.getThisUpdateOfCurrentCRL(caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public byte[] getEncodedCRL(X509CertWithDBCertId caCert, BigInteger crlNumber)
    {
        try
        {
            return queryExecutor.getEncodedCRL(caCert, crlNumber);
        } catch (Exception e)
        {
            LOG.error("Could not get CRL ca={}: error message: {}",
                    caCert.getSubject(),
                    e.getMessage());
            LOG.debug("Exception", e);
            return null;
        }
    }

    public int cleanupCRLs(X509CertWithDBCertId caCert, int numCRLs)
    {
        try
        {
            return queryExecutor.cleanupCRLs(caCert, numCRLs);
        } catch (Exception e)
        {
            LOG.error("Could not cleanup CRLs ca={}: error message: {}",
                    caCert.getSubject(),
                    e.getMessage());
            LOG.debug("Exception", e);
            return 0;
        }
    }

    public boolean certIssuedForSubject(X509CertWithDBCertId caCert,
            String sha1FpSubject)
    throws OperationException
    {
        try
        {
            return queryExecutor.certIssuedForSubject(caCert, sha1FpSubject);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public CertStatus getCertStatusForSubject(X509CertWithDBCertId caCert, X500Principal subject)
    {
        try
        {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (DataAccessException e)
        {
            LOG.error("queryExecutor.getCertStatusForSubject. DataAccessException: {}", e.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", e);
            return CertStatus.Unknown;
        }
    }

    public CertStatus getCertStatusForSubject(X509CertWithDBCertId caCert, X500Name subject)
    {
        try
        {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (DataAccessException e)
        {
            final String message = "queryExecutor.getCertStatusForSubject";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return CertStatus.Unknown;
        }
    }

    /**
     * Returns the first serial number ascend sorted {@code numEntries} revoked certificates
     * which are not expired at {@code notExpiredAt} and their serial numbers are not less than
     * {@code startSerial}.
     * @param caCert
     * @param notExpiredAt
     * @param startSerial
     * @param numEntries
     * @return
     * @throws DataAccessException
     */
    public List<CertRevocationInfoWithSerial> getRevokedCertificates(X509CertWithDBCertId caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries,
            boolean onlyCACerts, boolean onlyUserCerts)
    throws OperationException
    {
        try
        {
            return queryExecutor.getRevokedCertificates(caCert, notExpiredAt, startSerial, numEntries,
                    onlyCACerts, onlyUserCerts);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public List<CertRevocationInfoWithSerial> getCertificatesForDeltaCRL(
            X509CertWithDBCertId caCert, BigInteger startSerial, int numEntries,
            boolean onlyCACerts, boolean onlyUserCerts)
    throws OperationException
    {
        try
        {
            return queryExecutor.getCertificatesForDeltaCRL(caCert, startSerial, numEntries,
                    onlyCACerts, onlyUserCerts);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public List<BigInteger> getCertSerials(X509CertWithDBCertId caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries, boolean onlyRevoked,
            boolean onlyCACerts, boolean onlyUserCerts)
    throws OperationException
    {
        try
        {
            return queryExecutor.getSerialNumbers(caCert, notExpiredAt, startSerial, numEntries, onlyRevoked,
                    onlyCACerts, onlyUserCerts);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public List<BigInteger> getExpiredCertSerials(X509CertWithDBCertId caCert,
            long expiredAt, int numEntries, String certprofile, String userLike)
    throws OperationException
    {
        try
        {
            return queryExecutor.getExpiredSerialNumbers(caCert, expiredAt, numEntries, certprofile, userLike);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public int getNumOfExpiredCerts(X509CertWithDBCertId caCert, long expiredAt,
            String certprofile, String userLike)
    throws OperationException
    {
        try
        {
            return queryExecutor.getNumOfExpiredCerts(caCert, expiredAt, certprofile, userLike);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public List<Integer> getPublishQueueEntries(X509CertWithDBCertId caCert,
            String publisherName, int numEntries)
    throws OperationException
    {
        try
        {
            return queryExecutor.getPublishQueueEntries(caCert, publisherName, numEntries);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertWithRevocationInfo getCertWithRevocationInfo(X509CertWithDBCertId caCert,
            BigInteger serial)
    throws OperationException
    {
        try
        {
            return queryExecutor.getCertWithRevocationInfo(caCert, serial);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForSerial(X509CertWithDBCertId caCert, BigInteger serial)
    throws OperationException, CertificateException
    {
        try
        {
            return queryExecutor.getCertificateInfo(caCert, serial);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public Long getGreatestSerialNumber(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.getGreatestSerialNumber(caCert);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean isHealthy()
    {
        return queryExecutor.isHealthy();
    }

    public SubjectKeyProfileBundle getLatestCert(X509CertWithDBCertId caCert, String subjectFp,
            String keyFp, String profile)
    throws OperationException
    {
        try
        {
            return queryExecutor.getLatestCert(caCert, subjectFp, keyFp, profile);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean isCertForSubjectIssued(X509CertWithDBCertId caCert, String subjectFp)
    throws OperationException
    {
        return isCertForSubjectIssued(caCert, subjectFp, null);
    }

    public boolean isCertForSubjectIssued(X509CertWithDBCertId caCert, String subjectFp, String profile)
    throws OperationException
    {
        try
        {
            return queryExecutor.isCertForSubjectIssued(caCert, subjectFp, profile);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean isCertForKeyIssued(X509CertWithDBCertId caCert, String keyFp)
    throws OperationException
    {
        return isCertForKeyIssued(caCert, keyFp, null);
    }

    public boolean isCertForKeyIssued(X509CertWithDBCertId caCert, String keyFp, String profile)
    throws OperationException
    {
        try
        {
            return queryExecutor.isCertForKeyIssued(caCert, keyFp, profile);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertificateInfo getCertificateInfoForId(X509CertWithDBCertId caCert, int certId)
    throws OperationException, CertificateException
    {
        try
        {
            return queryExecutor.getCertForId(caCert, certId);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public X509CertWithDBCertId getCertForId(int certId)
    throws OperationException
    {
        try
        {
            return queryExecutor.getCertForId(certId);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public String getLatestSN(X500Name nameWithSN)
    throws OperationException
    {
        try
        {
            return queryExecutor.getLatestSN(nameWithSN);
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public Long getNotBeforeOfFirstCertStartsWithCN(String commonName, String profileName)
    throws OperationException
    {
        try
        {
            return queryExecutor.getNotBeforeOfFirstCertStartsWithCN(commonName, profileName);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean containsCACertificates(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.containsCertificates(caCert, false);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean containsUserCertificates(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            return queryExecutor.containsCertificates(caCert, true);
        } catch (DataAccessException e)
        {
            LOG.debug("DataAccessException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public long nextSerial(X509CertWithDBCertId caCert, String seqName)
    throws OperationException
    {
        try
        {
            return queryExecutor.nextSerial(caCert, seqName);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void commitNextSerialIfLess(String caName, long nextSerial)
    throws OperationException
    {
        try
        {
            queryExecutor.commitNextSerialIfLess(caName, nextSerial);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void markMaxSerial(X509CertWithDBCertId caCert, String seqName)
    throws OperationException
    {
        try
        {
            queryExecutor.markMaxSerial(caCert, seqName);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void commitNextCrlNo(String caName, int nextCrlNo)
    throws OperationException
    {
        try
        {
            queryExecutor.commitNextCrlNoIfLess(caName, nextCrlNo);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void addCa(X509CertWithDBCertId caCert)
    throws OperationException
    {
        try
        {
            queryExecutor.addCa(caCert);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void addRequestorName(String name)
    throws OperationException
    {
        try
        {
            queryExecutor.addRequestorName(name);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void addPublisherName(String name)
    throws OperationException
    {
        try
        {
            queryExecutor.addPublisherName(name);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void addCertprofileName(String name)
    throws OperationException
    {
        try
        {
            queryExecutor.addCertprofileName(name);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public boolean addCertInProcess(String fpKey, String fpSubject)
    throws OperationException
    {
        try
        {
            return queryExecutor.addCertInProcess(fpKey, fpSubject);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void delteCertInProcess(String fpKey, String fpSubject)
    throws OperationException
    {
        try
        {
            queryExecutor.deleteCertInProcess(fpKey, fpSubject);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }

    public void deleteCertsInProcessOlderThan(Date time)
    throws OperationException
    {
        try
        {
            queryExecutor.deleteCertsInProcessOlderThan(time);
        } catch (DataAccessException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
    }
}
