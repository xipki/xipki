/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.publisher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;

/**
 * @author Lijun Liao
 */

class CertStatusStoreQueryExecutor
{
    private static final Logger LOG = LoggerFactory.getLogger(CertStatusStoreQueryExecutor.class);

    private AtomicInteger cert_id;

    private final DataSourceWrapper dataSource;

    private final IssuerStore issuerStore;

    private final boolean publishGoodCerts;

    CertStatusStoreQueryExecutor(DataSourceWrapper dataSource, boolean publishGoodCerts)
    throws SQLException, NoSuchAlgorithmException
    {
        this.dataSource = dataSource;
        int maxCertId = dataSource.getMax(null, "CERT", "ID");
        this.cert_id = new AtomicInteger(maxCertId + 1);

        this.issuerStore = initIssuerStore();
        this.publishGoodCerts = publishGoodCerts;
    }

    private IssuerStore initIssuerStore()
    throws SQLException
    {
        final String sql = "SELECT ID, SUBJECT, SHA1_FP_CERT, CERT FROM ISSUER";
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            rs = ps.executeQuery();
            List<IssuerEntry> caInfos = new LinkedList<>();
            while(rs.next())
            {
                int id = rs.getInt("ID");
                String subject = rs.getString("SUBJECT");
                String hexSha1Fp = rs.getString("SHA1_FP_CERT");
                String b64Cert = rs.getString("CERT");

                IssuerEntry caInfoEntry = new IssuerEntry(id, subject, hexSha1Fp, b64Cert);
                caInfos.add(caInfoEntry);
            }

            return new IssuerStore(caInfos);
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    void addIssuer(X509CertificateWithMetaInfo issuer)
    throws CertificateEncodingException, SQLException
    {
        getIssuerId(issuer);
    }

    /**
     * @throws SQLException if there is problem while accessing database.
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    void addCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            String certProfile)
    throws SQLException, CertificateEncodingException
    {
        addCert(issuer, certificate, certProfile, null);
    }

    void addCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            String certProfile,
            CertRevocationInfo revInfo)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(issuer, certificate, certProfile, revInfo);
    }

    private void addOrUpdateCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            String certProfile,
            CertRevocationInfo revInfo)
    throws SQLException, CertificateEncodingException
    {
        boolean revoked = revInfo != null;
        int issuerId = getIssuerId(issuer);
        BigInteger serialNumber = certificate.getCert().getSerialNumber();
        boolean certRegistered = certRegistered(issuerId, serialNumber);

        if(publishGoodCerts == false && revoked == false && certRegistered == false )
        {
            return;
        }

        if(certRegistered)
        {
            final String sql = "UPDATE CERT" +
                    " SET LAST_UPDATE = ?, REVOKED = ?, REV_TIME = ?, REV_INVALIDITY_TIME = ?, REV_REASON = ?" +
                    " WHERE ISSUER_ID = ? AND SERIAL = ?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try
            {
                int idx = 1;
                ps.setLong(idx++, new Date().getTime()/1000);
                setBoolean(ps, idx++, revoked);
                if(revoked)
                {
                    ps.setLong(idx++, revInfo.getRevocationTime().getTime()/1000);
                    if(revInfo.getInvalidityTime() != null)
                    {
                        ps.setLong(idx++, revInfo.getInvalidityTime().getTime()/1000);
                    }else
                    {
                        ps.setNull(idx++, Types.INTEGER);
                    }
                    ps.setInt(idx++, revInfo.getReason().getCode());
                }
                else
                {
                    ps.setNull(idx++, Types.INTEGER); // rev_time
                    ps.setNull(idx++, Types.INTEGER); // rev_invalidity_time
                    ps.setNull(idx++, Types.INTEGER); // rev_reason
                }
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, serialNumber.longValue());
                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }
        }
        else
        {
            StringBuilder sb = new StringBuilder();
            sb.append("INSERT INTO CERT ");
            sb.append("(ID, LAST_UPDATE, SERIAL, SUBJECT");
            sb.append(", NOTBEFORE, NOTAFTER, REVOKED, ISSUER_ID, PROFILE");
            if(revoked)
            {
                sb.append(", REV_TIME, REV_INVALIDITY_TIME, REV_REASON");
            }
            sb.append(")");
            sb.append(" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?");
            if(revoked)
            {
                sb.append(", ?, ?, ?");
            }
            sb.append(")");

            final String SQL_ADD_CERT = sb.toString();
            PreparedStatement ps = borrowPreparedStatement(SQL_ADD_CERT);

            int certId = cert_id.getAndAdd(1);

            try
            {
                X509Certificate cert = certificate.getCert();
                int idx = 1;
                ps.setInt(idx++, certId);
                ps.setLong(idx++, System.currentTimeMillis()/1000);
                ps.setLong(idx++, serialNumber.longValue());
                ps.setString(idx++, certificate.getSubject());
                ps.setLong(idx++, cert.getNotBefore().getTime()/1000);
                ps.setLong(idx++, cert.getNotAfter().getTime()/1000);
                setBoolean(ps, idx++, revoked);
                ps.setInt(idx++, issuerId);
                ps.setString(idx++, certProfile);

                if(revoked)
                {
                    ps.setLong(idx++, revInfo.getRevocationTime().getTime()/1000);
                    if(revInfo.getInvalidityTime() != null)
                    {
                        ps.setLong(idx++, revInfo.getInvalidityTime().getTime()/1000);
                    }else
                    {
                        ps.setNull(idx++, Types.BIGINT);
                    }
                    ps.setInt(idx++, revInfo.getReason() == null? 0 : revInfo.getReason().getCode());
                }

                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }

            byte[] encodedCert = certificate.getEncodedCert();

            final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, CERT) VALUES (?, ?)";
            ps = borrowPreparedStatement(SQL_ADD_RAWCERT);

            try
            {
                int idx = 1;
                ps.setInt(idx++, certId);
                ps.setString(idx++, Base64.toBase64String(encodedCert));
                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }

            final String SQL_ADD_CERTHASH = "INSERT INTO CERTHASH "
                    + " (CERT_ID, SHA1_FP, SHA224_FP, SHA256_FP, SHA384_FP, SHA512_FP)"
                    + " VALUES (?, ?, ?, ?, ?, ?)";
            ps = borrowPreparedStatement(SQL_ADD_CERTHASH);

            try
            {
                int idx = 1;
                ps.setInt(idx++, certId);
                ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));
                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }
        }
    }

    void revokeCert(X509CertificateWithMetaInfo caCert,
            X509CertificateWithMetaInfo cert,
            CertRevocationInfo revInfo)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(caCert, cert, null, revInfo);
    }

    void unrevokeCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo cert)
    throws SQLException
    {
        Integer issuerId =  issuerStore.getIdForCert(issuer.getEncodedCert());
        if(issuerId == null)
        {
            return;
        }

        BigInteger serialNumber = cert.getCert().getSerialNumber();
        boolean certRegistered = certRegistered(issuerId, serialNumber);

        if(certRegistered == false)
        {
            return;
        }

        final String sql = "UPDATE CERT" +
                " SET LAST_UPDATE = ?, REVOKED = ?, REV_TIME = ?, REV_INVALIDITY_TIME = ?, REV_REASON = ?" +
                " WHERE ISSUER_ID = ? AND SERIAL = ?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try
        {
            int idx = 1;
            ps.setLong(idx++, new Date().getTime()/1000);
            setBoolean(ps, idx++, false);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setInt(idx++, issuerId);
            ps.setLong(idx++, serialNumber.longValue());
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    void removeCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo cert)
    throws SQLException
    {
        Integer issuerId =  issuerStore.getIdForCert(issuer.getEncodedCert());
        if(issuerId == null)
        {
            return;
        }

        final String sql = "DELETE FROM CERT" +
                " WHERE ISSUER_ID = ? AND SERIAL = ?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try
        {
            int idx = 1;
            ps.setInt(idx++, issuerId);
            ps.setLong(idx++, cert.getCert().getSerialNumber().longValue());
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    void revokeCa(X509CertificateWithMetaInfo caCert, CertRevocationInfo revocationInfo)
    throws SQLException, CertificateEncodingException
    {
        Date revocationTime = revocationInfo.getRevocationTime();
        Date invalidityTime = revocationInfo.getInvalidityTime();
        if(invalidityTime == null)
        {
            invalidityTime = revocationTime;
        }

        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER" +
                    " SET REVOKED = ?, REV_TIME = ?, REV_INVALIDITY_TIME = ?, REV_REASON = ?" +
                    " WHERE ID = ?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try
        {
            int idx = 1;
            setBoolean(ps, idx++, true);
            ps.setLong(idx++, revocationTime.getTime()/1000);
            ps.setLong(idx++, invalidityTime.getTime()/1000);
            ps.setInt(idx++, revocationInfo.getReason().getCode());
            ps.setInt(idx++, issuerId);
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    void unrevokeCa(X509CertificateWithMetaInfo caCert)
    throws SQLException, CertificateEncodingException
    {
        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER" +
                    " SET REVOKED = ?, REV_TIME = ?, REV_INVALIDITY_TIME = ?, REV_REASON = ?" +
                    " WHERE ID = ?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try
        {
            int idx = 1;
            setBoolean(ps, idx++, false);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setInt(idx++, issuerId);
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    private int getIssuerId(X509CertificateWithMetaInfo issuerCert)
    throws SQLException, CertificateEncodingException
    {
        Integer id =  issuerStore.getIdForCert(issuerCert.getEncodedCert());
        if(id != null)
        {
            return id.intValue();
        }

        final String sql =
                "INSERT INTO ISSUER" +
                " (ID, SUBJECT, "
                + "NOTBEFORE, NOTAFTER, "
                + "SHA1_FP_NAME, SHA1_FP_KEY, "
                + "SHA224_FP_NAME, SHA224_FP_KEY, "
                + "SHA256_FP_NAME, SHA256_FP_KEY, "
                + "SHA384_FP_NAME, SHA384_FP_KEY, "
                + "SHA512_FP_NAME, SHA512_FP_KEY,"
                + "SHA1_FP_CERT, CERT)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(sql);

        String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, issuerCert.getEncodedCert());

        Certificate bcCert = Certificate.getInstance(issuerCert.getEncodedCert());
        byte[] encodedName;
        try
        {
            encodedName = bcCert.getSubject().getEncoded("DER");
        } catch (IOException e)
        {
            throw new CertificateEncodingException(e);
        }
        byte[] encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

        id = issuerStore.getNextFreeId();
        try
        {
            String b64Cert = Base64.toBase64String(issuerCert.getEncodedCert());
            String subject = issuerCert.getSubject();
            int idx = 1;
            ps.setInt(idx++, id.intValue());
            ps.setString(idx++, subject);
            ps.setLong  (idx++, issuerCert.getCert().getNotBefore().getTime() / 1000);
            ps.setLong  (idx++, issuerCert.getCert().getNotAfter() .getTime() / 1000);
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedName));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedName));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedKey));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedName));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedKey));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedName));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedKey));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedName));
            ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedKey));
            ps.setString(idx++, hexSha1FpCert);
            ps.setString(idx++, b64Cert);

            ps.execute();

            IssuerEntry newInfo = new IssuerEntry(id.intValue(), subject, hexSha1FpCert, b64Cert);
            issuerStore.addIdentityEntry(newInfo);
        }finally
        {
            releaseDbResources(ps, null);
        }

        return id.intValue();
    }

    /**
     *
     * @return the next idle preparedStatement, {@code null} will be returned
     *         if no PreparedStament can be created within 5 seconds
     * @throws SQLException
     */
    private PreparedStatement borrowPreparedStatement(String sqlQuery)
    throws SQLException
    {
        PreparedStatement ps = null;
        Connection c = dataSource.getConnection();
        if(c != null)
        {
            ps = dataSource.prepareStatement(c,sqlQuery);
        }
        if(ps == null)
        {
            throw new SQLException("Cannot create prepared statement for " + sqlQuery);
        }
        return ps;
    }

    private boolean certRegistered(int issuerId, BigInteger serialNumber)
    throws SQLException
    {
        String sql = "COUNT(*) FROM CERT WHERE ISSUER_ID = ? AND SERIAL = ?";
        sql = dataSource.createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            int idx = 1;
            ps.setInt(idx++, issuerId);
            ps.setLong(idx++, serialNumber.longValue());

            rs = ps.executeQuery();
            if(rs.next())
            {
                return rs.getInt(1) > 0;
            }
        }finally
        {
            releaseDbResources(ps, rs);
        }

        return false;
    }

    boolean isHealthy()
    {
        final String sql = "SELECT ID FROM ISSUER";

        try
        {
            PreparedStatement ps = borrowPreparedStatement(sql);
            ResultSet rs = null;

            try
            {
                rs = ps.executeQuery();
            }finally
            {
                releaseDbResources(ps, rs);
            }
            return true;
        }catch(Exception e)
        {
            LOG.error("isHealthy(). {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("isHealthy()", e);
            return false;
        }
    }

    private void releaseDbResources(Statement ps, ResultSet rs)
    {
        dataSource.releaseResources(ps, rs);
    }

    private static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

}
