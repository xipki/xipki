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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Deque;
import java.util.LinkedList;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class DbDigestReader implements DigestReader
{
    private final int caId;
    private final DataSourceWrapper datasource;
    private final XipkiDbControl dbControl;
    private final Connection conn;
    private final String selectCertSql;
    private final PreparedStatement selectCertStmt;

    private final int totalAccount;
    private final String caSubjectName;
    private final X509Certificate caCert;
    private final int maxId;

    private final Deque<DbDigestEntry> certs = new LinkedList<>();
    private int nextId;

    public DbDigestReader(
            final DataSourceWrapper datasource,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean revokedOnly)
    throws DataAccessException, CertificateException, IOException
    {
        ParamUtil.assertNotNull("datasource", datasource);
        this.datasource = datasource;
        this.caId = caId;
        this.conn = datasource.getConnection();

        this.dbControl = new XipkiDbControl(dbSchemaType);

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        try
        {
            stmt = datasource.createStatement(conn);

            sql = "SELECT CERT FROM " + dbControl.getTblCa() + " WHERE ID=" + caId;
            rs = stmt.executeQuery(sql);
            if(rs.next() == false)
            {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            this.caCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
            this.caSubjectName = X509Util.getRFC4519Name(caCert.getSubjectX500Principal());
            rs.close();

            sql = "SELECT COUNT(*) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if(revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }
            rs = stmt.executeQuery(sql);

            this.totalAccount = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MAX(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if(revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            this.maxId = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MIN(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if(revokedOnly)
            {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            this.nextId = rs.next()
                    ? rs.getInt(1)
                    : 0;

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
                .append("=?");
            sb.append(" AND CERT.ID>=? AND CERT.ID<?");

            if(revokedOnly)
            {
                sql += " AND CERT." + dbControl.getColRevoked() + "=1";
            }

            sb.append("AND CERT.ID=")
                .append(dbControl.getTblCerthash())
                .append(".")
                .append(dbControl.getColCertId());
            sb.append(" ORDER BY CERT.ID ASC");

            this.selectCertSql = sb.toString();
        }catch(SQLException e)
        {
            throw datasource.translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        this.selectCertStmt = datasource.prepareStatement(conn, this.selectCertSql);
        try
        {
            this.selectCertStmt.setInt(1, caId);
        } catch (SQLException e)
        {
            close();
            throw datasource.translate(this.selectCertSql, e);
        }

        readNextCerts();
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
    public boolean hasNext()
    {
        return certs.isEmpty() == false;
    }

    @Override
    public DbDigestEntry nextCert()
    {
        DbDigestEntry next = certs.poll();
        if(next == null)
        {
            throw new IllegalStateException("reach end of the stream");
        }

        try
        {
            readNextCerts();
        } catch (DataAccessException e)
        {
            throw new IllegalStateException("error while retrieving next certificate: "
                    + e.getMessage());
        }

        return next;
    }

    private void readNextCerts()
    throws DataAccessException
    {
        ResultSet rs = null;

        while(certs.isEmpty() && nextId <= maxId)
        {
            try
            {
                selectCertStmt.setInt(2, nextId);

                this.nextId += 1000;
                selectCertStmt.setInt(3, nextId);

                rs = selectCertStmt.executeQuery();

                while(rs.next())
                {
                    String hash = rs.getString(dbControl.getColCerthash());
                    long serial = rs.getLong(dbControl.getColSerialNumber());
                    boolean revoked = rs.getBoolean(dbControl.getColRevoked());

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if(revoked)
                    {
                        revReason = rs.getInt(dbControl.getColRevReason());
                        revTime = rs.getLong(dbControl.getColRevTime());
                        revInvTime = rs.getLong(dbControl.getColRevInvTime());
                        if(revInvTime == 0)
                        {
                            revInvTime = null;
                        }
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    certs.addLast(cert);
                }
            } catch(SQLException e)
            {
                throw datasource.translate(dbControl.getCertSql(), e);
            }
            finally
            {
                releaseResources(null, rs);
            }
        }
    }

    public void close()
    {
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
