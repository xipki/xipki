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
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CertRevocationInfo;
import org.xipki.ca.server.CertStatus;
import org.xipki.database.api.DataSource;

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
                    new Object[]{certInfo.getCert().getCert().getSubjectX500Principal(),
                    Base64.toBase64String(certInfo.getCert().getEncodedCert()), e.getMessage()});
            LOG.debug("error", e);
            return false;
        }

        return true;
    }

    public byte[] revokeCertificate(X509CertificateWithMetaInfo caCert, BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws OperationException
    {
        try
        {
            byte[] revokedCert = queryExecutor.revokeCert(caCert, serialNumber, new Date(), reason, invalidityTime);
            if(revokedCert == null)
            {
                LOG.info("Could not revoke non-existing certificate issuer={}, serialNumber={}", caCert.getSubject(), serialNumber);
            }
            else
            {
                LOG.info("revoked certificate issuer={}, serialNumber={}", caCert.getSubject(), serialNumber);
            }

            return revokedCert;
        } catch (Exception e)
        {
            LOG.error("Could not revoke certificate issuer={} and serialNumber={}. {} Message: {}",
                    new Object[]{caCert.getSubject(), serialNumber, e.getClass().getName(), e.getMessage()});
            LOG.debug("error", e);
            return null;
        }
    }

    public boolean addCRL(X509CertificateWithMetaInfo cacert, X509CRL crl)
    {
        try
        {
            queryExecutor.addCRL(cacert, crl);
            return true;
        } catch (Exception e)
        {
            LOG.error("Could not add CRL ca={}, thisUpdate={}: {}, ",
                new Object[]{cacert.getCert().getSubjectX500Principal().getName(),
                    crl.getThisUpdate(), e.getMessage()});
            LOG.debug("Exception", e);
            return false;
        }
    }

    public int getNextFreeCRLNumber(X509CertificateWithMetaInfo cacert)
    throws SQLException, OperationException
    {
        return queryExecutor.getNextFreeCrlNumber(cacert);
    }

    public long getThisUpdateOfCurrentCRL(X509CertificateWithMetaInfo cacert)
    throws SQLException, OperationException
    {
        return queryExecutor.getThisUpdateOfCurrentCRL(cacert);
    }

    public byte[] getEncodedCurrentCRL(X509CertificateWithMetaInfo cacert)
    {
        try
        {
            return queryExecutor.getEncodedCRL(cacert);
        } catch (Exception e)
        {
            LOG.error("Could not get CRL ca={}: error message: {}",
                    cacert.getCert().getSubjectX500Principal().getName(),
                    e.getMessage());
            LOG.debug("Exception", e);
            return null;
        }
    }

    public int cleanupCRLs(X509CertificateWithMetaInfo cacert, int numCRLs)
    {
        try
        {
            return queryExecutor.cleanupCRLs(cacert, numCRLs);
        } catch (Exception e)
        {
            LOG.error("Could not cleanup CRLs ca={}: error message: {}",
                    cacert.getCert().getSubjectX500Principal().getName(),
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

    public List<Integer> getCertIdsForPublicKey(X509CertificateWithMetaInfo caCert, byte[] encodedSubjectPublicKey)
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
    public List<CertRevocationInfo> getRevokedCertificates(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        return queryExecutor.getRevokedCertificates(caCert, notExpiredAt, startSerial, numEntries);
    }

    /**
     *
     * @param caCert
     * @param notExpiredAt could be null.
     * @param startSerial
     * @param numEntries
     * @return
     * @throws SQLException
     * @throws OperationException
     */
    public List<BigInteger> getCertSerials(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        return queryExecutor.getSerialNumbers(caCert, notExpiredAt, startSerial, numEntries);
    }

    public byte[] getEncodedCertificate(X509CertificateWithMetaInfo caCert, BigInteger serial)
    throws SQLException, OperationException
    {
        return queryExecutor.getEncodedCertificate(caCert, serial);
    }

    public CertWithRevocationInfo getCertificate(List<Integer> certIds, String sha1FpSubject, String certProfile)
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
