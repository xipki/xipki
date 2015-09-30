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

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.IDRange;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.internal.DigestDBEntrySet;
import org.xipki.pki.ca.dbtool.diffdb.internal.IdentifiedDbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.XipkiDbControl;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class XipkiDbDigestReader extends DbDigestReader
{
    private class XipkiDbRetriever
    implements Retriever
    {
        private Connection conn;
        private PreparedStatement selectCertStmt;

        public XipkiDbRetriever()
        throws DataAccessException
        {
            this.conn = datasource.getConnection();
            try
            {
                selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
            } catch (DataAccessException e)
            {
                datasource.returnConnection(conn);
                throw e;
            }

        }

        @Override
        public void run()
        {
            while (!stop.get())
            {
                try
                {
                    IDRange idRange = inQueue.take();
                    query(idRange);
                } catch (InterruptedException e)
                {
                }
            }

            releaseResources(selectCertStmt, null);
            datasource.returnConnection(conn);
            selectCertStmt = null;
        }

        private void query(
                final IDRange idRange)
        {
            DigestDBEntrySet result = new DigestDBEntrySet(idRange.getFrom());

            ResultSet rs = null;
            try
            {
                selectCertStmt.setInt(1, idRange.getFrom());
                selectCertStmt.setInt(2, idRange.getTo() + 1);

                rs = selectCertStmt.executeQuery();

                while (rs.next())
                {
                    String hash = rs.getString(dbControl.getColCerthash());
                    long serial = rs.getLong(dbControl.getColSerialNumber());
                    boolean revoked = rs.getBoolean(dbControl.getColRevoked());

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked)
                    {
                        revReason = rs.getInt(dbControl.getColRevReason());
                        revTime = rs.getLong(dbControl.getColRevTime());
                        revInvTime = rs.getLong(dbControl.getColRevInvTime());
                        if (revInvTime == 0)
                        {
                            revInvTime = null;
                        }
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    int id = rs.getInt("ID");
                    result.addEntry(new IdentifiedDbDigestEntry(cert, id));
                }
            } catch (Exception e)
            {
                if (e instanceof SQLException)
                {
                    e = datasource.translate(selectCertSql, (SQLException) e);
                }
                result.setException(e);
            }
            finally
            {
                releaseResources(null, rs);
            }

            outQueue.add(result);
        }
    }

    private final int caId;
    private final XipkiDbControl dbControl;
    private final Connection conn;
    private final String selectCertSql;
    private final String numCertSql;
    private final PreparedStatement numCertStmt;

    public static XipkiDbDigestReader getInstance(
            final DataSourceWrapper datasource,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean revokedOnly,
            final int numThreads)
    throws Exception
    {
        ParamUtil.assertNotNull("datasource", datasource);
        Connection conn = datasource.getConnection();

        XipkiDbControl dbControl = new XipkiDbControl(dbSchemaType);

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        X509Certificate caCert;
        int totalAccount;
        int minId;
        int maxId;

        try
        {
            stmt = datasource.createStatement(conn);

            sql = "SELECT CERT FROM " + dbControl.getTblCa() + " WHERE ID=" + caId;
            rs = stmt.executeQuery(sql);
            if (!rs.next())
            {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            caCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
            rs.close();

            sql = "SELECT COUNT(*) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }
            rs = stmt.executeQuery(sql);

            totalAccount = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MAX(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            maxId = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MIN(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            minId = rs.next()
                    ? rs.getInt(1)
                    : 1;

            return new XipkiDbDigestReader(datasource, caCert, revokedOnly,
                    totalAccount, minId, maxId, numThreads, dbSchemaType, caId);
        } catch (SQLException e)
        {
            throw datasource.translate(sql, e);
        } finally
        {
            releaseResources(stmt, rs);
        }
    }

    private XipkiDbDigestReader(
            final DataSourceWrapper datasource,
            final X509Certificate caCert,
            final boolean revokedOnly,
            final int totalAccount,
            final int minId,
            final int maxId,
            final int numThreads,
            final DbSchemaType dbSchemaType,
            final int caId)
    throws Exception
    {
        super(datasource, caCert, revokedOnly, totalAccount, minId, maxId, numThreads);

        this.caId = caId;
        this.conn = datasource.getConnection();
        this.dbControl = new XipkiDbControl(dbSchemaType);

        StringBuilder sb = new StringBuilder();
        sb.append("SELECT ID,");
        sb.append(dbControl.getColSerialNumber()).append(",");
        sb.append(dbControl.getColRevoked()).append(",");
        sb.append(dbControl.getColRevReason()).append(",");
        sb.append(dbControl.getColRevTime()).append(",");
        sb.append(dbControl.getColRevInvTime()).append(",");
        sb.append(dbControl.getColCerthash());
        sb.append(" FROM CERT INNER JOIN ")
            .append(dbControl.getTblCerthash());
        sb.append(" ON CERT.")
            .append(dbControl.getColCaId())
            .append("=").append(caId);
        sb.append(" AND CERT.ID>=? AND CERT.ID<?");

        if (revokedOnly)
        {
            sb.append(" AND CERT.")
                .append(dbControl.getColRevoked()).
                append("=1");
        }

        sb.append(" AND CERT.ID=")
            .append(dbControl.getTblCerthash())
            .append(".")
            .append(dbControl.getColCertId());

        this.selectCertSql = sb.toString();

        this.numCertSql = "SELECT COUNT(*) FROM CERT WHERE CA_ID=" + caId
                + " AND ID>=? AND ID<=?";

        this.numCertStmt = datasource.prepareStatement(conn, this.numCertSql);

        if (!init())
        {
            throw new Exception("could not initialize the EjbcaDigestReader");
        }
    }

    @Override
    protected int getNumSkippedCerts(
            final int fromId,
            final int toId,
            final int numCerts)
    throws DataAccessException
    {
        if (fromId > toId)
        {
            return 0;
        }

        ResultSet rs = null;
        try
        {
            numCertStmt.setInt(1, fromId);
            numCertStmt.setInt(2, toId);
            rs = numCertStmt.executeQuery();
            int n = rs.next()
                    ? rs.getInt(1)
                    : 0;
            return (n < numCerts)
                    ? n - numCerts
                    : 0;
        } catch (SQLException e)
        {
            throw datasource.translate(numCertSql, e);
        } finally
        {
            releaseResources(null, rs);
        }

    }

    public void close()
    {
        super.close();

        releaseResources(numCertStmt, null);
        datasource.returnConnection(conn);
    }

    public int getCaId()
    {
        return caId;
    }

    @Override
    protected Retriever getRetriever()
    throws DataAccessException
    {
        return new XipkiDbRetriever();
    }
}
