/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.diffdb.io;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;

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

    public XipkiDigestExportReader(DataSourceWrapper datasource,
            XipkiDbControl dbControl, int numRowsPerSelect) throws Exception {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.dbControl = ParamUtil.requireNonNull("dbControl", dbControl);
        this.numRowsPerSelect = ParamUtil.requireMin("numRowsPerSelect", numRowsPerSelect, 1);

        this.selectCertSql = dbControl.certSql(datasource, numRowsPerSelect);

        Connection conn = datasource.getConnection();
        try {
            selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
        } catch (DataAccessException ex) {
            datasource.returnConnection(conn);
            throw ex;
        }
    }

    public List<IdentifiedDbDigestEntry> readCerts(long startId) throws DataAccessException {
        List<IdentifiedDbDigestEntry> ret = new ArrayList<>(numRowsPerSelect);

        ResultSet rs = null;
        try {
            selectCertStmt.setLong(1, startId);
            rs = selectCertStmt.executeQuery();

            while (rs.next()) {
                int caId = rs.getInt(dbControl.colCaId());
                long id = rs.getLong("ID");
                String hash = rs.getString(dbControl.colCerthash());
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
