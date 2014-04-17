/*
 * Copyright 2014 xipki.org
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
import java.security.cert.X509Certificate;
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
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CertRevocationInfo;
import org.xipki.ca.server.CertStatus;
import org.xipki.ca.server.X509CA;
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


    public boolean certificateAdded(CertificateInfo certInfo)
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
            LOG.error("error", e);
            return false;
        }

        return true;
    }

    public int certificateRevoked(X509Certificate cert, CRLReason reason,
            Date invalidityTime)
    {
        BigInteger serialNumber = cert.getSerialNumber();

        return certificateRevoked(cert.getIssuerX500Principal(), serialNumber, reason, invalidityTime);
    }

    public int certificateRevoked(X500Principal issuer, BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    {
        try
        {
            boolean revocated = queryExecutor.revocateCert(issuer, serialNumber, new Date(), reason, invalidityTime);
            if(revocated)
            {
                LOG.info("Could not revocate non-existing certificate issuer={}, serialNumber={}", issuer, serialNumber);
            }
            else
            {
                LOG.info("revocated certificate issuer={}, serialNumber={}", issuer, serialNumber);
            }

            return revocated ? X509CA.CERT_REVOCATED : X509CA.CERT_NOT_EXISTS;
        } catch (SQLException e)
        {
            LOG.error("Could not revocate certificate issuer={}, serial={}: {}",
                    new Object[]{issuer, serialNumber, e.getMessage()});
            return X509CA.CERT_REVOCATION_EXCEPTION;
        }
    }

    public boolean crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl)
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
            LOG.error("Exception", e);
            return false;
        }
    }

    public int getNextFreeCRLNumber(X509CertificateWithMetaInfo cacert) throws SQLException, OperationException
    {
        return queryExecutor.getNextFreeCrlNumber(cacert);
    }

    public long getThisUpdateOfCurrentCRL(X509CertificateWithMetaInfo cacert) throws SQLException, OperationException
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
            LOG.error("Exception", e);
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
            LOG.error("Exception", e);
            return 0;
        }
    }

    public boolean certIssued(X509CertificateWithMetaInfo caCert,
            String sha1FpSubject)
    {
        try
        {
            return queryExecutor.certIssued(caCert, sha1FpSubject);
        } catch (OperationException e)
        {
            LOG.error("queryExecutor.certIssued", e);
            return false;
        } catch (SQLException e)
        {
            LOG.error("queryExecutor.certIssued", e);
            return false;
        }
    }

    public boolean certIssued(X509CertificateWithMetaInfo caCert, byte[] encodedSubjectPublicKey)
    {
        try
        {
            return queryExecutor.certIssued(caCert, encodedSubjectPublicKey);
        } catch (OperationException e)
        {
            LOG.error("queryExecutor.certIssued", e);
            return false;
        } catch (SQLException e)
        {
            LOG.error("queryExecutor.certIssued", e);
            return false;
        }
    }

    public CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, X500Principal subject)
    {
        try
        {
            return queryExecutor.getCertStatusForSubject(caCert, subject);
        } catch (SQLException e)
        {
            LOG.error("queryExecutor.getCertStatusForSubject", e);
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
            LOG.error("queryExecutor.getCertStatusForSubject", e);
            return CertStatus.Unknown;
        }
    }

    /**
     * Returns the first serial number ascend sorted {@code numEntries} revocated certificates
     * which are not expired at {@code notExpiredAt} and their serial numbers are not less than
     * {@code startSerial}.
     * @param caCert
     * @param notExpiredAt
     * @param startSerial
     * @param numEntries
     * @return
     * @throws SQLException
     */
    public List<CertRevocationInfo> getRevocatedCertificates(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        return queryExecutor.getRevocatedCertificates(caCert, notExpiredAt, startSerial, numEntries);
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
