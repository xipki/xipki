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

package org.xipki.pki.ca.dbtool.diffdb;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.diffdb.internal.CertsBundle;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.internal.EjbcaCACertExtractor;
import org.xipki.security.api.HashCalculator;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class EjbcaDbDigestReader implements DigestReader
{
    private static class IdentifiedDbDigestEntry
    {
        final DbDigestEntry content;
        final int id;

        public IdentifiedDbDigestEntry(DbDigestEntry content, int id)
        {
            this.content = content;
            this.id = id;
        }
    }

    private final int caId;
    private final DataSourceWrapper datasource;
    private final Connection conn;
    private final String selectCertSql;
    private final String numCertSql;
    private final PreparedStatement selectCertStmt;
    private final PreparedStatement numCertStmt;
    private final boolean revokedOnly;

    private final int totalAccount;
    private final String caSubjectName;
    private final String caFingerprint;
    private final X509Certificate caCert;
    private final int maxId;

    private final Deque<IdentifiedDbDigestEntry> certs = new LinkedList<>();
    private int nextId;

    public EjbcaDbDigestReader(
            final DataSourceWrapper datasource,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean revokedOnly)
    throws Exception
    {
        ParamUtil.assertNotNull("datasource", datasource);
        this.datasource = datasource;
        this.caId = caId;
        this.conn = datasource.getConnection();
        this.revokedOnly = revokedOnly;

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        try
        {
            stmt = datasource.createStatement(conn);

            sql = "SELECT data FROM CAData WHERE cAId=" + caId;
            rs = stmt.executeQuery(sql);
            if(rs.next() == false)
            {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            String caData = rs.getString("data");
            rs.close();

            this.caCert = EjbcaCACertExtractor.extractCACert(caData);
            this.caSubjectName = X509Util.getRFC4519Name(caCert.getSubjectX500Principal());
            this.caFingerprint = HashCalculator.hexSha1(caCert.getEncoded()).toLowerCase();

            // special case
            StringBuilder sb = new StringBuilder();
            sb.append("SELECT id,serialNumber,status,revocationDate,revocationReason,base64Cert");
            sb.append(" FROM CertificateData ");
            sb.append(" WHERE cAFingerprint=fingerprint");
            sb.append(" AND cAFingerprint != '").append(caFingerprint).append("'");
            if(revokedOnly)
            {
                sql += " AND status=40";
            }
            sql = sb.toString();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String b64Cert = rs.getString("base64Cert");
                X509Certificate jceCert = X509Util.parseBase64EncodedCert(b64Cert);
                if(jceCert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())
                        == false)
                {
                    continue;
                }

                String hash = HashCalculator.hexSha1(jceCert.getEncoded());
                long serial = rs.getLong("serialNumber");
                int status = rs.getInt("status");
                boolean revoked = (status != 20);

                Integer revReason = null;
                Long revTime = null;
                Long revInvTime = null;

                if(revoked)
                {
                    revReason = rs.getInt("revocationReason");
                    long rev_timeInMs = rs.getLong("revocationDate");
                    // rev_time is milliseconds, convert it to seconds
                    revTime = rev_timeInMs / 1000;
                }

                DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                        revInvTime, hash);
                int id = rs.getInt("id");
                certs.addLast(new IdentifiedDbDigestEntry(cert, id));
            }

            // get account
            sql = "SELECT COUNT(*) FROM CertificateData WHERE cAFingerprint='"
                    + caFingerprint + "'";
            if(revokedOnly)
            {
                sql += " AND status=40";
            }
            rs = stmt.executeQuery(sql);

            int account = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();
            this.totalAccount = account + certs.size();

            sql = "SELECT MAX(id) FROM CertificateData WHERE cAFingerprint='" + caFingerprint + "'";
            if(revokedOnly)
            {
                sql += " AND status=40";
            }

            rs = stmt.executeQuery(sql);
            this.maxId = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MIN(id) FROM CertificateData WHERE cAFingerprint='" + caFingerprint + "'";
            if(revokedOnly)
            {
                sql += " AND status=40";
            }

            rs = stmt.executeQuery(sql);
            this.nextId = rs.next()
                    ? rs.getInt(1)
                    : 1;

            sb = new StringBuilder();
            sb.append("SELECT id,fingerprint,status,revocationDate,revocationReason");
            sb.append(" FROM CertificateData ");
            sb.append(" WHERE cAFingerprint='").append(caFingerprint).append("'");
            sb.append(" AND id>=? AND id<?");
            if(revokedOnly)
            {
                sb.append(" AND status=40");
            }
            this.selectCertSql = sb.toString();

            sb = new StringBuilder();
            sb.append("SELECT COUNT(*) FROM CertificateData");
            sb.append(" WHERE cAFingerprint='").append(caFingerprint).append("'");
            sb.append(" AND id>=? AND id<?");
            this.numCertSql = sb.toString();
        }catch(SQLException e)
        {
            throw datasource.translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        this.selectCertStmt = datasource.prepareStatement(conn, this.selectCertSql);
        this.numCertStmt = datasource.prepareStatement(conn, this.numCertSql);
    }

    @Override
    public X509Certificate getCaCert()
    {
        return caCert;
    }

    @Override
    public String getCaSubjectName()
    {
        return caSubjectName;
    }

    @Override
    public int getTotalAccount()
    {
        return totalAccount;
    }

    @Override
    public CertsBundle nextCerts(
            final int n)
    throws DataAccessException
    {
        if(nextId > maxId && certs.isEmpty())
        {
            return null;
        }

        List<IdentifiedDbDigestEntry> entries = new ArrayList<>(n);
        int k = 0;
        while(true)
        {
            if(certs.isEmpty())
            {
                readNextCerts();
            }

            IdentifiedDbDigestEntry next = certs.poll();
            if(next == null)
            {
                break;
            }

            entries.add(next);
            k++;
            if(k >= n)
            {
                break;
            }
        }

        if(k == 0)
        {
            return null;
        }

        int numSkipped = 0;
        if(revokedOnly)
        {
            int numCertsInThisRange = getNumCerts(entries.get(0).id,
                    entries.get(k - 1).id);
            numSkipped = numCertsInThisRange - k;
        }

        List<Long> serialNumbers = new ArrayList<>(k);
        Map<Long, DbDigestEntry> certsMap = new HashMap<>(k);
        for(IdentifiedDbDigestEntry m : entries)
        {
            long sn = m.content.getSerialNumber();
            serialNumbers.add(sn);
            certsMap.put(sn, m.content);
        }

        return new CertsBundle(numSkipped, certsMap, serialNumbers);
    }

    private int getNumCerts(
            final int fromId,
            final int toId)
    throws DataAccessException
    {
        if(fromId > toId)
        {
            return 0;
        }

        ResultSet rs = null;
        try
        {
            numCertStmt.setInt(1, fromId);
            numCertStmt.setInt(2, toId);
            rs = numCertStmt.executeQuery();
            return rs.next()
                    ? rs.getInt(1)
                    : 0;
        }catch(SQLException e)
        {
            throw datasource.translate(numCertSql, e);
        } finally
        {
            releaseResources(null, rs);
        }

    }

    private void readNextCerts()
    throws DataAccessException
    {
        ResultSet rs = null;

        while(certs.isEmpty() && nextId <= maxId)
        {
            try
            {
                selectCertStmt.setInt(1, nextId);

                this.nextId += 1000;
                selectCertStmt.setInt(2, nextId);

                rs = selectCertStmt.executeQuery();

                while(rs.next())
                {
                    String hash = rs.getString("fingerprint");
                    long serial = rs.getLong("serialNumber");
                    int status = rs.getInt("status");
                    boolean revoked = (status == 40);

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if(revoked)
                    {
                        revReason = rs.getInt("revocationReason");
                        long rev_timeInMs = rs.getLong("revocationDate");
                        // rev_time is milliseconds, convert it to seconds
                        revTime = rev_timeInMs / 1000;
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    int id = rs.getInt("id");
                    certs.addLast(new IdentifiedDbDigestEntry(cert, id));
                }
            } catch(SQLException e)
            {
                throw datasource.translate(selectCertSql, e);
            }
            finally
            {
                releaseResources(null, rs);
            }
        }
    }

    public void close()
    {
        releaseResources(numCertStmt, null);
        releaseResources(selectCertStmt, null);
        datasource.returnConnection(conn);
    }

    protected void releaseResources(
            final Statement ps,
            final ResultSet rs)
    {
        if(ps != null)
        {
            try
            {
                ps.close();
            }catch(SQLException e)
            {
            }
        }

        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(SQLException e)
            {
            }
        }
    }

    public int getCaId()
    {
        return caId;
    }

}
