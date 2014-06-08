/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.store;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CertRevocationInfoWithSerial;
import org.xipki.ca.server.CertStatus;
import org.xipki.database.api.DataSource;
import org.xipki.security.common.CertRevocationInfo;

public class CertificateStore
{
    private static final Logger LOG = LoggerFactory.getLogger(CertificateStore.class);
    private final CertStoreQueryExecutor queryExecutor;

    public CertificateStore(DataSource dataSource)
    throws SQLException
    {
        if(dataSource == null)
            throw new IllegalArgumentException("dataSource is null");

        this.queryExecutor = new CertStoreQueryExecutor(dataSource);
    }

    public boolean addCertificate(CertificateInfo certInfo)
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

    public CertWithRevocationInfo revokeCertificate(X509CertificateWithMetaInfo caCert,
            BigInteger serialNumber, CertRevocationInfo revInfo, boolean force)
    throws OperationException
    {
        try
        {
            CertWithRevocationInfo revokedCert = queryExecutor.revokeCert(caCert, serialNumber, revInfo, force);
            if(revokedCert == null)
            {
                LOG.info("Could not revoke non-existing certificate issuer={}, serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("revoked certificate issuer={}, serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return revokedCert;
        } catch (SQLException e)
        {
            LOG.debug("SQLException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        }
    }

    public X509CertificateWithMetaInfo unrevokeCertificate(X509CertificateWithMetaInfo caCert,
            BigInteger serialNumber, boolean force)
    throws OperationException
    {
        try
        {
            X509CertificateWithMetaInfo unrevokedCert = queryExecutor.unrevokeCert(caCert, serialNumber, force);
            if(unrevokedCert == null)
            {
                LOG.info("Could not unrevoke non-existing certificate issuer={}, serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("revoked certificate issuer={}, serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return unrevokedCert;
        } catch (SQLException e)
        {
            LOG.debug("SQLException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        }
    }

    public X509CertificateWithMetaInfo removeCertificate(X509CertificateWithMetaInfo caCert,
            BigInteger serialNumber)
    throws OperationException
    {
        try
        {
            X509CertificateWithMetaInfo removedCert = queryExecutor.removeCert(caCert, serialNumber);
            if(removedCert == null)
            {
                LOG.info("Could not remove non-existing certificate issuer={}, serialNumber={}",
                    caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("revoked certificate issuer={}, serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return removedCert;
        } catch (SQLException e)
        {
            LOG.debug("SQLException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        }
    }

    public boolean addCRL(X509CertificateWithMetaInfo caCert, X509CRL crl)
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

    public int getNextFreeCRLNumber(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        return queryExecutor.getNextFreeCrlNumber(caCert);
    }

    public long getThisUpdateOfCurrentCRL(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        return queryExecutor.getThisUpdateOfCurrentCRL(caCert);
    }

    public byte[] getEncodedCurrentCRL(X509CertificateWithMetaInfo caCert)
    {
        try
        {
            return queryExecutor.getEncodedCRL(caCert);
        } catch (Exception e)
        {
            LOG.error("Could not get CRL ca={}: error message: {}",
                    caCert.getSubject(),
                    e.getMessage());
            LOG.debug("Exception", e);
            return null;
        }
    }

    public int cleanupCRLs(X509CertificateWithMetaInfo caCert, int numCRLs)
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

    public boolean certIssuedForSubject(X509CertificateWithMetaInfo caCert,
            String sha1FpSubject)
    throws OperationException
    {
        try
        {
            return queryExecutor.certIssued(caCert, sha1FpSubject);
        } catch (SQLException e)
        {
            LOG.debug("SQLException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        }
    }

    public List<Integer> getCertIdsForPublicKey(X509CertificateWithMetaInfo caCert,
            byte[] encodedSubjectPublicKey)
    throws OperationException
    {
        try
        {
            return queryExecutor.getCertIdsForPublicKey(caCert, encodedSubjectPublicKey);
        } catch (SQLException e)
        {
            LOG.debug("SQLException", e);
            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
        }
    }

    public CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, X500Principal subject)
    {
        try
        {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (SQLException e)
        {
            LOG.error("queryExecutor.getCertStatusForSubject. SQLException: {}", e.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", e);
            return CertStatus.Unknown;
        }
    }

    public CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, X500Name subject)
    {
        try
        {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (SQLException e)
        {
            LOG.error("queryExecutor.getCertStatusForSubject. SQLException: {}", e.getMessage());
            LOG.debug("queryExecutor.getCertStatusForSubject", e);
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
     * @throws SQLException
     */
    public List<CertRevocationInfoWithSerial> getRevokedCertificates(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        return queryExecutor.getRevokedCertificates(caCert, notExpiredAt, startSerial, numEntries);
    }

    public List<BigInteger> getCertSerials(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        return queryExecutor.getSerialNumbers(caCert, notExpiredAt, startSerial, numEntries);
    }

    public CertWithRevocationInfo getCertWithRevocationInfo(X509CertificateWithMetaInfo caCert,
            BigInteger serial)
    throws SQLException, OperationException
    {
        return queryExecutor.getCertWithRevocationInfo(caCert, serial);
    }

    public CertWithRevokedInfo getCertificate(List<Integer> certIds, String sha1FpSubject, String certProfile)
    throws SQLException, OperationException
    {
        return queryExecutor.getCertificate(certIds, sha1FpSubject, certProfile);
    }

    public CertificateInfo getCertificateInfo(X509CertificateWithMetaInfo caCert, BigInteger serial)
    throws SQLException, OperationException, CertificateException
    {
        return queryExecutor.getCertificateInfo(caCert, serial);
    }

    public Long getGreatestSerialNumber(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        return queryExecutor.getGreatestSerialNumber(caCert);
    }

    public boolean isHealthy()
    {
        return queryExecutor.isHealthy();
    }
}
