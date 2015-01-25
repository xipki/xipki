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

package org.xipki.ca.server.impl.publisher;

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

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.LogUtil;
import org.xipki.datasource.api.DataSourceWrapper;

/**
 * @author Lijun Liao
 */

class OCSPStoreQueryExecutor
{
    private static final Logger LOG = LoggerFactory.getLogger(OCSPStoreQueryExecutor.class);

    private final DataSourceWrapper dataSource;

    private final IssuerStore issuerStore;

    private final boolean publishGoodCerts;

    OCSPStoreQueryExecutor(DataSourceWrapper dataSource, boolean publishGoodCerts)
    throws SQLException, NoSuchAlgorithmException
    {
        this.dataSource = dataSource;
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

    /**
     * @throws SQLException if there is problem while accessing database.
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    void addCert(X509CertWithId issuer,
            X509CertWithId certificate,
            String certProfile)
    throws SQLException, CertificateEncodingException
    {
        addCert(issuer, certificate, certProfile, null);
    }

    void addCert(X509CertWithId issuer,
            X509CertWithId certificate,
            String certProfile,
            CertRevocationInfo revInfo)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(issuer, certificate, certProfile, revInfo);
    }

    private void addOrUpdateCert(X509CertWithId issuer,
            X509CertWithId certificate,
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
                    " SET LAST_UPDATE=?, REVOKED=?, REV_TIME=?, REV_INVALIDITY_TIME=?, REV_REASON=?" +
                    " WHERE ISSUER_ID=? AND SERIAL=?";
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

            final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, CERT) VALUES (?, ?)";

            final String SQL_ADD_CERTHASH = "INSERT INTO CERTHASH "
                    + " (CERT_ID, SHA1_FP, SHA224_FP, SHA256_FP, SHA384_FP, SHA512_FP)"
                    + " VALUES (?, ?, ?, ?, ?, ?)";

            int certId = nextCertId();

            PreparedStatement[] pss = borrowPreparedStatements(SQL_ADD_CERT, SQL_ADD_RAWCERT, SQL_ADD_CERTHASH);
            // all statements have the same connection
            Connection conn = null;

            try
            {
                PreparedStatement ps_addcert = pss[0];
                PreparedStatement ps_addRawcert = pss[1];
                PreparedStatement ps_addCerthash = pss[2];
                conn = ps_addcert.getConnection();

                // CERT
                X509Certificate cert = certificate.getCert();
                int idx = 1;
                ps_addcert.setInt(idx++, certId);
                ps_addcert.setLong(idx++, System.currentTimeMillis()/1000);
                ps_addcert.setLong(idx++, serialNumber.longValue());
                ps_addcert.setString(idx++, certificate.getSubject());
                ps_addcert.setLong(idx++, cert.getNotBefore().getTime()/1000);
                ps_addcert.setLong(idx++, cert.getNotAfter().getTime()/1000);
                setBoolean(ps_addcert, idx++, revoked);
                ps_addcert.setInt(idx++, issuerId);
                ps_addcert.setString(idx++, certProfile);

                if(revoked)
                {
                    ps_addcert.setLong(idx++, revInfo.getRevocationTime().getTime()/1000);
                    if(revInfo.getInvalidityTime() != null)
                    {
                        ps_addcert.setLong(idx++, revInfo.getInvalidityTime().getTime()/1000);
                    }else
                    {
                        ps_addcert.setNull(idx++, Types.BIGINT);
                    }
                    ps_addcert.setInt(idx++, revInfo.getReason() == null? 0 : revInfo.getReason().getCode());
                }

                // RAWCERT
                byte[] encodedCert = certificate.getEncodedCert();
                idx = 1;
                ps_addRawcert.setInt(idx++, certId);
                ps_addRawcert.setString(idx++, Base64.toBase64String(encodedCert));

                // CERTHASH
                idx = 1;
                ps_addCerthash.setInt(idx++, certId);
                ps_addCerthash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                ps_addCerthash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                ps_addCerthash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                ps_addCerthash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                ps_addCerthash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));

                final boolean origAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);
                try
                {
                    try
                    {
                        ps_addcert.executeUpdate();
                        ps_addRawcert.executeUpdate();
                        ps_addCerthash.executeUpdate();
                        conn.commit();
                    }catch(SQLException e)
                    {
                        conn.rollback();
                        throw e;
                    }
                }
                finally
                {
                    conn.setAutoCommit(origAutoCommit);
                }
            } catch(SQLException e)
            {
                LOG.error("datasource {} SQLException while adding certificate with id {}: {}",
                        dataSource.getDatasourceName(), certId, e.getMessage());
                throw e;
            }
            finally
            {
                try
                {
                    for(PreparedStatement ps : pss)
                    {
                        try
                        {
                            ps.close();
                        }catch(Throwable t)
                        {
                            LOG.warn("Could not close PreparedStatement", t);
                        }
                    }
                }finally
                {
                    dataSource.returnConnection(conn);
                }
            }
        }
    }

    void revokeCert(X509CertWithId caCert,
            X509CertWithId cert,
            String certProfile,
            CertRevocationInfo revInfo)
    throws SQLException, CertificateEncodingException
    {
        addOrUpdateCert(caCert, cert, certProfile, revInfo);
    }

    void unrevokeCert(X509CertWithId issuer,
            X509CertWithId cert)
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

        if(publishGoodCerts)
        {
            final String sql = "UPDATE CERT" +
                    " SET LAST_UPDATE=?, REVOKED=?, REV_TIME=?, REV_INVALIDITY_TIME=?, REV_REASON=?" +
                    " WHERE ISSUER_ID=? AND SERIAL=?";
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
        } else
        {
            final String sql = "DELETE FROM CERT" +
                    " WHERE ISSUER_ID=? AND SERIAL=?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try
            {
                int idx = 1;
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, serialNumber.longValue());
                ps.executeUpdate();
            }finally
            {
                releaseDbResources(ps, null);
            }
        }

    }

    void removeCert(X509CertWithId issuer,
            X509CertWithId cert)
    throws SQLException
    {
        Integer issuerId =  issuerStore.getIdForCert(issuer.getEncodedCert());
        if(issuerId == null)
        {
            return;
        }

        final String sql = "DELETE FROM CERT WHERE ISSUER_ID=? AND SERIAL=?";
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

    void revokeCa(X509CertWithId caCert, CertRevocationInfo revocationInfo)
    throws SQLException, CertificateEncodingException
    {
        Date revocationTime = revocationInfo.getRevocationTime();
        Date invalidityTime = revocationInfo.getInvalidityTime();
        if(invalidityTime == null)
        {
            invalidityTime = revocationTime;
        }

        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER SET REVOKED=?, REV_TIME=?, REV_INVALIDITY_TIME=?, REV_REASON=? WHERE ID=?";
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

    void unrevokeCa(X509CertWithId caCert)
    throws SQLException, CertificateEncodingException
    {
        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER SET REVOKED=?, REV_TIME=?, REV_INVALIDITY_TIME=?, REV_REASON=? WHERE ID=?";
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

    private int getIssuerId(X509CertWithId issuerCert)
    throws SQLException, CertificateEncodingException
    {
        Integer id = issuerStore.getIdForCert(issuerCert.getEncodedCert());
        if(id == null)
        {
            throw new IllegalStateException("Could not find issuer, "
                    + "please start XiPKI in master mode first the restart this XiPKI system");
        }
        return id.intValue();
    }

    void addIssuer(X509CertWithId issuerCert)
    throws CertificateEncodingException, SQLException
    {
        if(issuerStore.getIdForCert(issuerCert.getEncodedCert()) != null)
        {
            return;
        }

        String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, issuerCert.getEncodedCert());

        Certificate bcCert = Certificate.getInstance(issuerCert.getEncodedCert());
        byte[] encodedName;
        try
        {
            encodedName = bcCert.getSubject().getEncoded("DER");
        } catch (IOException e)
        {
            throw new CertificateEncodingException(e.getMessage(), e);
        }
        byte[] encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

        long maxId = dataSource.getMax(null, "ISSUER", "ID");
        int id = (int) maxId + 1;

        final String sql =
                "INSERT INTO ISSUER (ID, SUBJECT, NOTBEFORE, NOTAFTER," +
                " SHA1_FP_NAME, SHA1_FP_KEY, SHA224_FP_NAME, SHA224_FP_KEY, SHA256_FP_NAME, SHA256_FP_KEY," +
                " SHA384_FP_NAME, SHA384_FP_KEY, SHA512_FP_NAME, SHA512_FP_KEY,SHA1_FP_CERT, CERT)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try
        {
            String b64Cert = Base64.toBase64String(issuerCert.getEncodedCert());
            String subject = issuerCert.getSubject();
            int idx = 1;
            ps.setInt(idx++, id);
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

            IssuerEntry newInfo = new IssuerEntry(id, subject, hexSha1FpCert, b64Cert);
            issuerStore.addIdentityEntry(newInfo);
        }finally
        {
            releaseDbResources(ps, null);
        }
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

    private PreparedStatement[] borrowPreparedStatements(String... sqlQueries)
    throws SQLException
    {
        PreparedStatement[] pss = new PreparedStatement[sqlQueries.length];

        Connection c = dataSource.getConnection();
        if(c != null)
        {
            final int n = sqlQueries.length;
            for(int i = 0; i < n; i++)
            {
                pss[i] = dataSource.prepareStatement(c, sqlQueries[i]);
                if(pss[i] == null)
                {
                    for(int j = 0; j < i; j++)
                    {
                        try
                        {
                            pss[j].close();
                        }catch(Throwable t)
                        {
                            LOG.warn("Could not close preparedStatement", t);
                        }
                    }
                    try
                    {
                        c.close();
                    }catch(Throwable t)
                    {
                        LOG.warn("Could not close connection", t);
                    }

                    throw new SQLException("Cannot create prepared statement for " + sqlQueries[i]);
                }
            }
        }

        return pss;
    }

    private boolean certRegistered(int issuerId, BigInteger serialNumber)
    throws SQLException
    {
        final String sql = dataSource.createFetchFirstSelectSQL(
                "COUNT(*) FROM CERT WHERE ISSUER_ID=? AND SERIAL=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

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
            ResultSet rs = null;
            PreparedStatement ps = borrowPreparedStatement(sql);

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
            final String message = "isHealthy()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }
    }

    private void releaseDbResources(Statement ps, ResultSet rs)
    {
        dataSource.releaseResources(ps, rs);
    }

    int nextCertId()
    throws SQLException
    {
        Connection conn = dataSource.getConnection();
        try
        {
            while(true)
            {
                int certId = (int) dataSource.nextSeqValue("CERT_ID");
                if(dataSource.columnExists(conn, "CERT", "ID", certId) == false)
                {
                    return certId;
                }
            }
        } finally
        {
            dataSource.returnConnection(conn);
        }
    }

    private static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

}
