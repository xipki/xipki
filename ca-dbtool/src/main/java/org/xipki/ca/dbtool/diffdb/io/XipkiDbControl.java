/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDbControl {

    private final String tblCa;

    private final String tblCerthash;

    private final String colCaId;

    private final String colCerthash;

    private final String caSql;

    private final String certCoreSql;

    public XipkiDbControl(final DbSchemaType dbSchemaType) {
        ParamUtil.requireNonNull("dbSchemaType", dbSchemaType);

        if (dbSchemaType == DbSchemaType.XIPKI_CA_v2) {
            tblCa = "CA";
            tblCerthash = "CRAW";
            colCaId = "CA_ID";
            colCerthash = "SHA1";
        } else if (dbSchemaType == DbSchemaType.XIPKI_OCSP_v2) {
            tblCa = "ISSUER";
            tblCerthash = "CHASH";
            colCaId = "IID";
            colCerthash = "S1";
        } else {
            throw new RuntimeException("unsupported DbSchemaType " + dbSchemaType);
        }

        // CA SQL
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT ID,CERT FROM ").append(tblCa);
        this.caSql = sb.toString();

        // CERT CORE SQL
        sb.delete(0, sb.length());
        sb.append("ID,").append(colCaId).append(",SN,REV,RR,RT,RIT,").append(colCerthash);
        sb.append(" FROM CERT INNER JOIN ").append(tblCerthash);
        sb.append(" ON CERT.ID>=? AND CERT.ID=").append(tblCerthash).append(".CID");
        this.certCoreSql = sb.toString();
    } // constructor

    public String tblCa() {
        return tblCa;
    }

    public String tblCerthash() {
        return tblCerthash;
    }

    public String colCaId() {
        return colCaId;
    }

    public String colCerthash() {
        return colCerthash;
    }

    public String caSql() {
        return caSql;
    }

    public String certSql(final DataSourceWrapper datasource, final int rows) {
        return datasource.buildSelectFirstSql(rows, "ID ASC", certCoreSql);
    }

}
