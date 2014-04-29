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

package org.xipki.ca.server.publisher;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
import org.xipki.database.api.DataSource;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;

class CertStatusStoreQueryExecutor
{
    private static final Logger LOG = LoggerFactory.getLogger(CertStatusStoreQueryExecutor.class);

    private AtomicInteger cert_id;

    private final DataSource dataSource;

    private final IssuerStore issuerStore;

    private final HashCalculator hashCalculator;

    CertStatusStoreQueryExecutor(DataSource dataSource)
    throws SQLException, NoSuchAlgorithmException
    {
        this.dataSource = dataSource;
        this.hashCalculator = new HashCalculator();

        final String sql = "SELECT MAX(ID) FROM CERT";
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            rs = ps.executeQuery();
            rs.next();
            cert_id = new AtomicInteger(rs.getInt(1) + 1);
        } finally
        {
            releaseDbResources(ps, rs);
        }

        this.issuerStore = initIssuerStore();
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
            List<IssuerEntry> caInfos = new LinkedList<IssuerEntry>();
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
            X509CertificateWithMetaInfo certificate)
    throws SQLException, CertificateEncodingException
    {
        addCert(issuer, certificate, false, null, null, null);
    }

    void addCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            boolean revocated,
            Date revocationTime,
            Integer revocationReason,
            Date invalidityTime)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(issuer, certificate, revocated,
                revocationTime, revocationReason, invalidityTime);
    }

    private void addOrUpdateCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            boolean revocated,
            Date revocationTime,
            Integer revocationReason,
            Date invalidityTime)
    throws SQLException, CertificateEncodingException
    {
        if(revocated)
        {
            if(revocationTime == null)
            {
                throw new IllegalArgumentException("revocationTime could not be null");
            }
        }

        byte[] encodedCert = certificate.getEncodedCert();
        String sha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);
        boolean certRegistered = certRegistered(sha1FpCert);

        if(certRegistered)
        {
            int issuerId = getIssuerId(issuer);

            final String sql = "UPDATE CERT" +
                    " SET LAST_UPDATE = ?, REVOCATED = ?, REV_TIME = ?, REV_INVALIDITY_TIME = ?, REV_REASON = ?" +
                    " WHERE ISSUER_ID = ? AND SERIAL = ?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try
            {
                int idx = 1;
                ps.setLong(idx++, new Date().getTime()/1000);
                ps.setBoolean(idx++, revocated);
                if(revocated)
                {
                    ps.setLong(idx++, revocationTime.getTime()/1000);
                    if(invalidityTime != null)
                    {
                        ps.setLong(idx++, invalidityTime.getTime()/1000);
                    }else
                    {
                        ps.setNull(idx++, Types.INTEGER);
                    }
                    ps.setInt(idx++, revocationReason);
                }
                else
                {
                    ps.setNull(idx++, Types.INTEGER); // rev_time
                    ps.setNull(idx++, Types.INTEGER); // rev_invalidity_time
                    ps.setNull(idx++, Types.INTEGER); // rev_reason
                }
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, certificate.getCert().getSerialNumber().intValue());
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
            sb.append(", NOTBEFORE, NOTAFTER, REVOCATED, ISSUER_ID");
            if(revocated)
            {
                sb.append(", REV_TIME, REV_INVALIDITY_TIME, REV_REASON");
            }
            sb.append(")");
            sb.append(" VALUES (?, ?, ?, ?, ?, ?, ?, ?");
            if(revocated)
            {
                sb.append(", ?, ?, ?");
            }
            sb.append(")");

            final String SQL_ADD_CERT = sb.toString();
            PreparedStatement ps = borrowPreparedStatement(SQL_ADD_CERT);

            int certId = cert_id.getAndAdd(1);

            try
            {
                int issuerId = getIssuerId(issuer);

                X509Certificate cert = certificate.getCert();
                int idx = 1;
                ps.setInt(idx++, certId);
                ps.setLong(idx++, System.currentTimeMillis()/1000);
                ps.setString(idx++, cert.getSerialNumber().toString());
                ps.setString(idx++, cert.getSubjectX500Principal().getName());
                ps.setLong(idx++, cert.getNotBefore().getTime()/1000);
                ps.setLong(idx++, cert.getNotAfter().getTime()/1000);
                ps.setBoolean(idx++, revocated);
                ps.setInt(idx++, issuerId);

                if(revocated)
                {
                    ps.setLong(idx++, revocationTime.getTime()/1000);
                    if(invalidityTime != null)
                    {
                        ps.setLong(idx++, invalidityTime.getTime()/1000);
                    }else
                    {
                        ps.setNull(idx++, Types.BIGINT);
                    }
                    ps.setInt(idx++, revocationReason == null? 0 : revocationReason.intValue());
                }

                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }

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
                ps.setString(idx++, sha1FpCert);
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));
                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }
        }
    }

    void revocateCert(X509CertificateWithMetaInfo caCert,
            X509CertificateWithMetaInfo cert,
            Date revocationTime,
            int revocationReason,
            Date invalidityTime)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(caCert, cert, true, revocationTime, revocationReason, invalidityTime);
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
                + "SHA1_FP_NAME, SHA1_FP_KEY, "
                + "SHA224_FP_NAME, SHA224_FP_KEY, "
                + "SHA256_FP_NAME, SHA256_FP_KEY, "
                + "SHA384_FP_NAME, SHA384_FP_KEY, "
                + "SHA512_FP_NAME, SHA512_FP_KEY,"
                + "SHA1_FP_CERT, CERT)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(sql);

        String hexSha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, issuerCert.getEncodedCert());

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
            String subject = issuerCert.getCert().getSubjectX500Principal().getName();
            int idx = 1;
            ps.setInt(idx++, id.intValue());
            ps.setString(idx++, subject);
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedName));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedName));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedKey));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedName));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedKey));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedName));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedKey));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedName));
            ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedKey));
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
        Connection c = dataSource.getConnection(5000);
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

    private boolean certRegistered(String sha1FpCert)
    throws SQLException
    {
        String sql = "count(*) FROM CERTHASH WHERE SHA1_FP=?";
        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            int idx = 1;
            ps.setString(idx++, sha1FpCert);

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

    private String createFetchFirstSelectSQL(String coreSql, int rows)
    {
        String prefix = "SELECT";
        String suffix = "";

        switch(dataSource.getDatabaseType())
        {
            case DB2:
                suffix = "FETCH FIRST " + rows + " ROWS ONLY";
                break;
            case INFORMIX:
                prefix = "SELECT FIRST " + rows;
                break;
            case MSSQL2000:
                prefix = "SELECT TOP " + rows;
                break;
            case MYSQL:
                suffix = "LIMIT " + rows;
                break;
            case ORACLE:
                 suffix = "AND ROWNUM <= " + rows;
                break;
            case POSTGRESQL:
                suffix = " FETCH FIRST " + rows + " ROWS ONLY";
                break;
            default:
                break;
        }

        return prefix + " " + coreSql + " " + suffix;
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

    private void releaseDbResources(PreparedStatement ps, ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("Cannot return close ResultSet", t);
            }
        }

        try
        {
            Connection conn = ps.getConnection();
            ps.close();
            dataSource.returnConnection(conn);
        }catch(Throwable t)
        {
            LOG.warn("Cannot return prepared statement and connection", t);
        }
    }

}
