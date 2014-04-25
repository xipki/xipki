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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.CertBasedRequestorInfo;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CertRevocationInfo;
import org.xipki.ca.server.CertStatus;
import org.xipki.database.api.DataSource;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class CertStoreQueryExecutor
{
    private static final Logger LOG = LoggerFactory.getLogger(CertStoreQueryExecutor.class);

    private AtomicInteger cert_id;

    private final MessageDigest sha1md;
    private final DataSource dataSource;

    private final CertBasedIdentityStore caInfoStore;
    private final CertBasedIdentityStore requestorInfoStore;
    private final CertprofileStore certprofileStore;

    CertStoreQueryExecutor(DataSource dataSource)
    throws SQLException
    {
        this.dataSource = dataSource;
        try
        {
            this.sha1md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Should not reach here. Error message: " + e.getMessage());
        }

        String sql = "SELECT MAX(id) FROM cert";
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

        this.caInfoStore = initCertBasedIdentyStore("cainfo");
        this.requestorInfoStore = initCertBasedIdentyStore("requestorinfo");
        this.certprofileStore = initCertprofileStore();
    }

    private CertBasedIdentityStore initCertBasedIdentyStore(String table)
    throws SQLException
    {
        final String SQL_GET_CAINFO = "SELECT id, subject, sha1_fp_cert, cert FROM " + table;
        PreparedStatement ps = borrowPreparedStatement(SQL_GET_CAINFO);

        ResultSet rs = null;
        try
        {
            rs = ps.executeQuery();
            List<CertBasedIdentityEntry> caInfos = new LinkedList<CertBasedIdentityEntry>();
            while(rs.next())
            {
                int id = rs.getInt("id");
                String subject = rs.getString("subject");
                String hexSha1Fp = rs.getString("sha1_fp_cert");
                String b64Cert = rs.getString("cert");

                CertBasedIdentityEntry caInfoEntry = new CertBasedIdentityEntry(id, subject, hexSha1Fp, b64Cert);
                caInfos.add(caInfoEntry);
            }

            return new CertBasedIdentityStore(table, caInfos);
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    private CertprofileStore initCertprofileStore()
    throws SQLException
    {
        final String sql = "SELECT id, name FROM certprofileinfo";
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            rs = ps.executeQuery();
            Map<String, Integer> entries = new HashMap<String, Integer>();

            while(rs.next())
            {
                int id = rs.getInt("id");
                String name = rs.getString("name");
                entries.put(name, id);
            }

            return new CertprofileStore(entries);
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
    void addCert(X509CertificateWithMetaInfo issuer,
            X509CertificateWithMetaInfo certificate,
            byte[] encodedSubjectPublicKey,
            String certprofileName,
            RequestorInfo requestor,
            String user)
    throws SQLException, OperationException
    {
        final String SQL_ADD_CERT =
                "INSERT INTO cert " +
                "(id, last_update, serial, subject,"
                + " notbefore, notafter, revocated,"
                + " certprofileinfo_id, cainfo_id,"
                + " requestorinfo_id, user_id, sha1_fp_pk, sha1_fp_subject)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(SQL_ADD_CERT);

        int certId = cert_id.getAndAdd(1);

        try
        {
            int caId = getCaId(issuer);
            int certprofileId = getCertprofileId(certprofileName);

            X509Certificate cert = certificate.getCert();
            int idx = 1;
            ps.setInt(idx++, certId);
            ps.setLong(idx++, System.currentTimeMillis()/1000);
            ps.setLong(idx++, cert.getSerialNumber().longValue());
            ps.setString(idx++, certificate.getSubject());
            ps.setLong(idx++, cert.getNotBefore().getTime()/1000);
            ps.setLong(idx++, cert.getNotAfter().getTime()/1000);
            ps.setBoolean(idx++, false);
            ps.setInt(idx++, certprofileId);
            ps.setInt(idx++, caId);

            Integer requestorId = null;
            Integer userId = null;
            if(requestor instanceof CertBasedRequestorInfo)
            {
                CertBasedRequestorInfo cmpRequestorInfo = (CertBasedRequestorInfo) requestor;
                if(cmpRequestorInfo.getCertificate() != null)
                {
                    requestorId = getRequestorId(cmpRequestorInfo.getCertificate());
                }

                if(user != null)
                {
                    userId = getUserId(user);
                }
            }

            if(requestorId != null)
            {
                ps.setInt(idx++, requestorId.intValue());
            }
            else
            {
                ps.setNull(idx++, Types.INTEGER);
            }

            if(userId != null)
            {
                ps.setInt(idx++, userId.intValue());
            }
            else
            {
                ps.setNull(idx++, Types.INTEGER);
            }

            ps.setString(idx++, fp(encodedSubjectPublicKey));
            String sha1_fp_subject = IoCertUtil.sha1sum_canonicalized_name(cert.getSubjectX500Principal());
            ps.setString(idx++, sha1_fp_subject);
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }

        final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, sha1_fp, cert) VALUES (?, ?, ?)";
        ps = borrowPreparedStatement(SQL_ADD_RAWCERT);

        String sha1_fp = fp(certificate.getEncodedCert());

        try
        {
            int idx = 1;
            ps.setInt(idx++, certId);
            ps.setString(idx++, sha1_fp);
            ps.setString(idx++, Base64.toBase64String(certificate.getEncodedCert()));
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    int getNextFreeCrlNumber(X509CertificateWithMetaInfo cacert)
    throws SQLException, OperationException
    {
        final String SQL = "SELECT max(crl_number) FROM crl WHERE cainfo_id=?";
        PreparedStatement ps = borrowPreparedStatement(SQL);
        ResultSet rs = null;

        try
        {
            int caId = getCaId(cacert);
            ps.setInt(1, caId);

            rs = ps.executeQuery();
            int maxCrlNumber = 0;
            if(rs.next())
            {
                maxCrlNumber = rs.getInt(1);
                if (maxCrlNumber < 0)
                {
                    maxCrlNumber = 0;
                }
            }

            return maxCrlNumber + 1;
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    Long getThisUpdateOfCurrentCRL(X509CertificateWithMetaInfo cacert)
    throws SQLException, OperationException
    {
        final String SQL = "SELECT max(thisUpdate) FROM crl WHERE cainfo_id=?";
        PreparedStatement ps = borrowPreparedStatement(SQL);
        ResultSet rs = null;

        try
        {
            int caId = getCaId(cacert);
            ps.setInt(1, caId);

            rs = ps.executeQuery();
            long thisUpdateOfCurrentCRL = 0;
            if(rs.next())
            {
                thisUpdateOfCurrentCRL = rs.getLong(1);
            }

            return thisUpdateOfCurrentCRL;
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    void addCRL(X509CertificateWithMetaInfo cacert,
            X509CRL crl)
    throws SQLException, CRLException, OperationException
    {
        byte[] encodedExtnValue = crl.getExtensionValue(Extension.cRLNumber.getId());
        Integer crlNumber = null;
        if(encodedExtnValue != null)
        {
            byte[] extnValue = DEROctetString.getInstance(encodedExtnValue).getOctets();
            crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue().intValue();
        }

        final String SQL = "INSERT INTO crl (cainfo_id, crl_number, thisUpdate, nextUpdate, crl) VALUES (?, ?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(SQL);

        try
        {
            int caId = getCaId(cacert);
            int idx = 1;

            ps.setInt(idx++, caId);
            if(crlNumber != null)
            {
                ps.setInt(idx++, crlNumber.intValue());
            }
            else
            {
                ps.setNull(idx++, Types.INTEGER);
            }
            Date d = crl.getThisUpdate();
            ps.setLong(idx++, d.getTime()/1000);
            d = crl.getNextUpdate();
            if(d != null)
            {
                ps.setLong(idx++, d.getTime()/1000);
            }
            else
            {
                ps.setNull(idx++, Types.BIGINT);
            }

            byte[] encodedCrl = crl.getEncoded();
            InputStream is = new ByteArrayInputStream(encodedCrl);
            ps.setBlob(idx++, is);

            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }
    }

    byte[] revocateCert(X509CertificateWithMetaInfo caCert, BigInteger serialNumber,
            Date revocationTime, CRLReason revocationReason,
            Date invalidityTime)
    throws OperationException, SQLException
    {
        byte[] encodedCert = getEncodedCertificate(caCert, serialNumber);
        if(encodedCert == null)
        {
            LOG.warn("Certificate with issuer={} and serialNumber={} does not exist", caCert.getSubject(), serialNumber);
            return null;
        }

        Integer caId = getCaId(caCert); // could not be null

        final String SQL_REVOCATE_CERT =
                "UPDATE cert" +
                " SET last_update=?, revocated = ?, rev_time = ?, rev_invalidity_time=?, rev_reason = ?" +
                " WHERE cainfo_id = ? AND serial = ?";
        PreparedStatement ps = borrowPreparedStatement(SQL_REVOCATE_CERT);

        try
        {
            int idx = 1;
            ps.setLong(idx++, new Date().getTime()/1000);
            ps.setBoolean(idx++, true);
            ps.setLong(idx++, revocationTime.getTime()/1000);
            if(invalidityTime != null)
            {
                ps.setLong(idx++, invalidityTime.getTime()/1000);
            }else
            {
                ps.setNull(idx++, Types.BIGINT);
            }

            ps.setInt(idx++, revocationReason.getValue().intValue());
            ps.setInt(idx++, caId.intValue());
            ps.setLong(idx++, serialNumber.longValue());

            int count = ps.executeUpdate();
            if(count != 1)
            {
                String message;
                if(count > 1)
                {
                    message = count + " rows modified, but exactly one is expected";
                }
                else
                {
                    message = "no row is modified, but exactly one is expected";
                }
                throw new OperationException(ErrorCode.System_Failure, message);
            }
        }finally
        {
            releaseDbResources(ps, null);
        }

        return encodedCert;
    }

    Long getGreatestSerialNumber(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        if(caCert == null)
        {
            throw new IllegalArgumentException("caCert is null");
        }

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return null;
        }

        String sql = "SELECT MAX(serial) FROM cert WHERE cainfo_id=?";
        PreparedStatement ps = borrowPreparedStatement(sql);
        ps.setInt(1, caId);
        ResultSet rs = null;

        try
        {
            rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        } finally
        {
            releaseDbResources(ps, rs);
        }
    }

    List<BigInteger> getSerialNumbers(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        if(caCert == null)
        {
            throw new IllegalArgumentException("caCert is null");
        }

        else if(numEntries < 1)
        {
            throw new IllegalArgumentException("numSerials is not positive");
        }

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return Collections.emptyList();
        }

        StringBuilder sb = new StringBuilder("serial FROM cert ");
        sb.append(" WHERE cainfo_id=? AND serial>?");
        if(notExpiredAt != null)
        {
            sb.append(" AND notafter>?");
        }
        sb.append(" ORDER BY serial ASC");

        final String sql = createFetchFirstSelectSQL(sb.toString(), numEntries);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            ps.setLong(idx++, (startSerial == null)? 0 : startSerial.longValue()-1);
            if(notExpiredAt != null)
            {
                ps.setLong(idx++, notExpiredAt.getTime()/1000 + 1);
            }
            rs = ps.executeQuery();

            List<BigInteger> ret = new ArrayList<BigInteger>();
            while(rs.next() && ret.size() < numEntries)
            {
                long serial = rs.getLong("serial");
                ret.add(BigInteger.valueOf(serial));
            }

            return ret;
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    byte[] getEncodedCRL(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        ParamChecker.assertNotNull("caCert", caCert);

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return null;
        }

        String sql = "thisUpdate, crl FROM crl WHERE cainfo_id=? ORDER BY thisUpdate DESC";
        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            rs = ps.executeQuery();

            byte[] encodedCrl = null;

            long current_thisUpdate = 0;
            // iterate all entries to make sure that the latest CRL will be returned
            while(rs.next())
            {
                long thisUpdate = rs.getLong("thisUpdate");
                if(thisUpdate >= current_thisUpdate)
                {
                    Blob blob = rs.getBlob("crl");
                    encodedCrl = readBlob(blob);
                    current_thisUpdate = thisUpdate;
                }
            }

            return encodedCrl;
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    public int cleanupCRLs(X509CertificateWithMetaInfo caCert, int numCRLs)
    throws SQLException, OperationException
    {
        if(numCRLs < 1)
        {
            throw new IllegalArgumentException("numCRLs is not positive");
        }

        ParamChecker.assertNotNull("caCert", caCert);
        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return 0;
        }

        String sql = "SELECT crl_number FROM crl WHERE cainfo_id=?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        List<Integer> crlNumbers = new LinkedList<Integer>();

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            rs = ps.executeQuery();

            while(rs.next())
            {
                int crlNumber = rs.getInt("crl_number");
                crlNumbers.add(crlNumber);
            }
        }finally
        {
            releaseDbResources(ps, rs);
        }

        int n = crlNumbers.size();
        Collections.sort(crlNumbers);

        int numCrlsToDelete = n - numCRLs;
        if(numCrlsToDelete < 1)
        {
            return 0;
        }

        int crlNumber = crlNumbers.get(numCrlsToDelete - 1);
        sql = "DELETE FROM crl WHERE cainfo_id=? AND crl_number<?";
        ps = borrowPreparedStatement(sql);

        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            ps.setInt(idx++, crlNumber + 1);
            ps.executeUpdate();
        }finally
        {
            releaseDbResources(ps, null);
        }

        return numCrlsToDelete;
    }
    private static byte[] readBlob(Blob blob)
    {
        InputStream is;
        try
        {
            is = blob.getBinaryStream();
        } catch (SQLException e)
        {
            String msg = "Could not getBinaryStream from Blob";
            LOG.warn(msg + " {}", e.getMessage());
            LOG.debug(msg, e);
            return null;
        }
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            byte[] buffer = new byte[2048];
            int readed;

            try
            {
                while((readed = is.read(buffer)) != -1)
                {
                    if(readed > 0)
                    {
                        out.write(buffer, 0, readed);
                    }
                }
            } catch (IOException e)
            {
                String msg = "Could not read CRL from Blob";
                LOG.warn(msg + " {}", e.getMessage());
                LOG.debug(msg, e);
                return null;
            }

            return out.toByteArray();
        }finally
        {
            try
            {
                is.close();
            }catch(IOException e)
            {
            }
        }
    }

    byte[] getEncodedCertificate(X509CertificateWithMetaInfo caCert, BigInteger serial)
    throws SQLException, OperationException
    {
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("serial", serial);

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return null;
        }

        String sql = "t2.cert cert"
                + " FROM cert t1, rawcert t2"
                + " WHERE t1.cainfo_id=? AND t1.serial=? AND t2.cert_id=t1.id";

        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            ps.setLong(idx++, serial.longValue());
            rs = ps.executeQuery();

            if(rs.next())
            {
                String b64Cert = rs.getString("cert");
                return b64Cert == null ? null : Base64.decode(b64Cert);
            }
        }finally
        {
            releaseDbResources(ps, null);
        }

        return null;
    }

    CertificateInfo getCertificateInfo(X509CertificateWithMetaInfo caCert, BigInteger serial)
    throws SQLException, OperationException, CertificateException
    {
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("serial", serial);

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return null;
        }

        final String col_certprofileinfo_id = "certprofileinfo_id";
        final String col_revocated = "revocated";
        final String col_rev_reason = "rev_reason";
        final String col_rev_time = "rev_time";
        final String col_rev_invalidity_time = "rev_invalidity_time";
        final String col_cert = "cert";

        String sql = "t1." + col_certprofileinfo_id + " " + col_certprofileinfo_id +
                ", t1." + col_revocated + " " + col_revocated +
                ", t1." + col_rev_reason + " " + col_rev_reason +
                ", t1." + col_rev_time + " " + col_rev_time +
                ", t1." + col_rev_invalidity_time + " " + col_rev_invalidity_time +
                ", t2." + col_cert + " " + col_cert +
                " FROM cert t1, rawcert t2" +
                " WHERE t1.cainfo_id=? AND t1.serial=? AND t2.cert_id=t1.id";

        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            ps.setLong(idx++, serial.longValue());
            rs = ps.executeQuery();

            if(rs.next())
            {
                String b64Cert = rs.getString(col_cert);
                byte[] encodedCert = Base64.decode(b64Cert);
                X509Certificate cert = IoCertUtil.parseCert(encodedCert);

                int certProfileInfo_id = rs.getInt(col_certprofileinfo_id);
                String certProfileName = certprofileStore.getName(certProfileInfo_id);

                X509CertificateWithMetaInfo certWithMeta = new X509CertificateWithMetaInfo(cert, encodedCert);

                CertificateInfo certInfo = new CertificateInfo(certWithMeta,
                        caCert, cert.getPublicKey().getEncoded(), certProfileName);

                boolean revocated = rs.getBoolean(col_revocated);
                certInfo.setRevocated(revocated);

                if(revocated)
                {
                    int rev_reason = rs.getInt(col_rev_reason);
                    certInfo.setRevocationReason(rev_reason);

                    long rev_time = rs.getLong(col_rev_time);
                    certInfo.setRevocationTime(new Date(rev_time * 1000));

                    long invalidity_time = rs.getLong(col_rev_invalidity_time);
                    certInfo.setInvalidityTime(new Date(invalidity_time * 1000));
                }

                return certInfo;
            }
        } catch (IOException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "IOException: " + e.getMessage());
        }finally
        {
            releaseDbResources(ps, rs);
        }

        return null;
    }

    List<CertRevocationInfo> getRevocatedCertificates(X509CertificateWithMetaInfo caCert,
            Date notExpiredAt, BigInteger startSerial, int numEntries)
    throws SQLException, OperationException
    {
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("notExpiredAt", notExpiredAt);

        if(numEntries < 1)
        {
            throw new IllegalArgumentException("numSerials is not positive");
        }

        Integer caId = getCaId(caCert);
        if(caId == null)
        {
            return Collections.emptyList();
        }

        String sql = "serial, rev_reason, rev_time, rev_invalidity_time"
                + " FROM cert"
                + " WHERE cainfo_id=? AND revocated=? AND serial>? AND notafter>?"
                + " ORDER BY serial ASC";

        sql = createFetchFirstSelectSQL(sql, numEntries);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId.intValue());
            ps.setBoolean(idx++, true);
            ps.setLong(idx++, startSerial.longValue()-1);
            ps.setLong(idx++, notExpiredAt.getTime()/1000 + 1);
            rs = ps.executeQuery();

            List<CertRevocationInfo> ret = new ArrayList<CertRevocationInfo>();
            while(rs.next() && ret.size() < numEntries)
            {
                long serial = rs.getLong("serial");
                int rev_reason = rs.getInt("rev_reason");
                long rev_time = rs.getLong("rev_time");
                long rev_invalidity_time = rs.getLong("rev_invalidity_time");
                CertRevocationInfo revInfo = new CertRevocationInfo(BigInteger.valueOf(serial),
                        rev_reason, new Date(1000 * rev_time), new Date(1000 * rev_invalidity_time));
                ret.add(revInfo);
            }

            return ret;
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, X500Principal subject)
    throws SQLException
    {
        return getCertStatusForSubject(caCert, subject.getName());
    }

    CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, X500Name subject)
    throws SQLException
    {
        return getCertStatusForSubject(caCert, subject.toString());
    }

    private CertStatus getCertStatusForSubject(X509CertificateWithMetaInfo caCert, String subject)
    throws SQLException
    {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId =  caInfoStore.getCaIdForCert(encodedCert);
        if(caId == null)
        {
            return CertStatus.Unknown;
        }

        String sql = "revocated FROM cert WHERE cainfo_id=? AND subject=?";
        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setString(idx++, subject);

            rs = ps.executeQuery();
            if(rs.next())
            {
                return rs.getBoolean("revocated") ? CertStatus.Revocated : CertStatus.Good;
            }
            else
            {
                return CertStatus.Unknown;
            }
        }finally
        {
            releaseDbResources(ps, rs);
        }
    }

    boolean certIssued(X509CertificateWithMetaInfo caCert, String sha1FpSubject)
    throws OperationException, SQLException
    {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId =  caInfoStore.getCaIdForCert(encodedCert);

        if(caId == null)
        {
            return false;
        }

        String sql = "count(*) FROM cert WHERE cainfo_id=? AND sha1_fp_subject=?";
        sql = createFetchFirstSelectSQL(sql, 1);

        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try
        {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setString(idx++, sha1FpSubject);

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

    boolean certIssued(X509CertificateWithMetaInfo caCert, byte[] encodedSubjectPublicKey)
    throws OperationException, SQLException
    {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId =  caInfoStore.getCaIdForCert(encodedCert);

        if(caId == null)
        {
            return false;
        }

        String sha1FpPk = fp(encodedSubjectPublicKey);

        String sql = "count(*) FROM cert"
                + " WHERE cainfo_id=? AND sha1_fp_pk=?";
        sql = createFetchFirstSelectSQL(sql, 1);
        PreparedStatement ps = borrowPreparedStatement(sql);

        ResultSet rs = null;
        try
        {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setString(idx++, sha1FpPk);

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

    private String fp(byte[] data)
    {
        synchronized (sha1md)
        {
            sha1md.reset();
            return Hex.toHexString(sha1md.digest(data)).toUpperCase();
        }
    }

    private int getCertBasedIdentityId(X509CertificateWithMetaInfo identityCert, CertBasedIdentityStore store)
    throws SQLException, OperationException
    {
        byte[] encodedCert = identityCert.getEncodedCert();
        Integer id =  store.getCaIdForCert(encodedCert);

        if(id != null)
        {
            return id.intValue();
        }

        String hexSha1Fp = fp(encodedCert);

        final String SQL_ADD_CAINFO =
                "INSERT INTO " + store.getTable() +
                " (id, subject, sha1_fp_cert, cert)" +
                " VALUES (?, ?, ?, ?)";
        PreparedStatement ps = borrowPreparedStatement(SQL_ADD_CAINFO);

        id = store.getNextFreeId();
        try
        {
            String b64Cert = Base64.toBase64String(encodedCert);
            String subject = identityCert.getSubject();
            int idx = 1;
            ps.setInt(idx++, id.intValue());
            ps.setString(idx++, subject);
            ps.setString(idx++, hexSha1Fp);
            ps.setString(idx++, b64Cert);

            ps.execute();

            CertBasedIdentityEntry newInfo = new CertBasedIdentityEntry(id.intValue(), subject, hexSha1Fp, b64Cert);
            store.addIdentityEntry(newInfo);
        }finally
        {
            releaseDbResources(ps, null);
        }

        return id.intValue();
    }

    private int getCaId(X509CertificateWithMetaInfo caCert)
    throws SQLException, OperationException
    {
        return getCertBasedIdentityId(caCert, caInfoStore);
    }

    private int getRequestorId(X509CertificateWithMetaInfo requestorCert)
    throws SQLException, OperationException
    {
        return getCertBasedIdentityId(requestorCert, requestorInfoStore);
    }

    private int getUserId(String user)
    {
        return 0; // FIXME: implement me
    }

    private int getCertprofileId(String certprofileName)
    throws SQLException
    {
        if(certprofileName == null)
        {
            return -1;
        }

        Integer id = certprofileStore.getId(certprofileName);
        if(id != null)
        {
            return id.intValue();
        }

        final String sql = "INSERT INTO certprofileinfo (id, name) VALUES (?, ?)";
        PreparedStatement ps = borrowPreparedStatement(sql);

        id = certprofileStore.getNextFreeId();
        try
        {
            int idx = 1;
            ps.setInt(idx++, id.intValue());
            ps.setString(idx++, certprofileName);

            ps.execute();
            certprofileStore.addProfileEntry(certprofileName, id);
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
            ps = c.prepareStatement(sqlQuery);
        }

        if(ps == null)
        {
            throw new SQLException("Cannot create prepared statement for " + sqlQuery);
        }

        return ps;
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

    boolean isHealthy()
    {
        final String sql = "SELECT id FROM cainfo";

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

}
