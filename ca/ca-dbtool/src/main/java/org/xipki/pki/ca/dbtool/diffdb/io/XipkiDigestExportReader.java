/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.dbtool.diffdb.io;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDigestExportReader {

    private static final Logger LOG = LoggerFactory.getLogger(XipkiDigestExportReader.class);

    private final DataSourceWrapper datasource;

    private final XipkiDbControl dbControl;

    private final String selectCertSql;

    private final PreparedStatement selectCertStmt;

    private final int numRowsPerSelect;

    public XipkiDigestExportReader(final DataSourceWrapper datasource,
            final XipkiDbControl dbControl, final int numRowsPerSelect) throws Exception {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.dbControl = ParamUtil.requireNonNull("dbControl", dbControl);
        this.numRowsPerSelect = ParamUtil.requireMin("numRowsPerSelect", numRowsPerSelect, 1);

        this.selectCertSql = dbControl.getCertSql(datasource, numRowsPerSelect);

        Connection conn = datasource.getConnection();
        try {
            selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
        } catch (DataAccessException ex) {
            datasource.returnConnection(conn);
            throw ex;
        }
    }

    public List<IdentifiedDbDigestEntry> readCerts(final long startId)
            throws DataAccessException {
        List<IdentifiedDbDigestEntry> ret = new ArrayList<>(numRowsPerSelect);

        ResultSet rs = null;
        try {
            selectCertStmt.setLong(1, startId);
            rs = selectCertStmt.executeQuery();

            while (rs.next()) {
                int caId = rs.getInt(dbControl.getColCaId());
                long id = rs.getLong("ID");
                String hash = rs.getString(dbControl.getColCerthash());
                BigInteger serial = new BigInteger(rs.getString("SN"), 16);
                boolean revoked = rs.getBoolean("REV");

                Integer revReason = null;
                Long revTime = null;
                Long revInvTime = null;

                if (revoked) {
                    revReason = rs.getInt("RR");
                    revTime = rs.getLong("RT");
                    revInvTime = rs.getLong("RIT");
                    if (revInvTime == 0) {
                        revInvTime = null;
                    }
                }

                DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                        revInvTime, hash);
                IdentifiedDbDigestEntry idCert = new IdentifiedDbDigestEntry(cert, id);
                idCert.setCaId(caId);

                ret.add(idCert);
            }
        } catch (SQLException ex) {
            LOG.error("could not export certificates from ID {}", startId);
            throw datasource.translate(selectCertSql, (SQLException) ex);
        } finally {
            DbToolBase.releaseResources(datasource, null, rs);
        }

        return ret;
    }

    public void stop() {
        datasource.releaseResources(selectCertStmt, null);
    }

}
