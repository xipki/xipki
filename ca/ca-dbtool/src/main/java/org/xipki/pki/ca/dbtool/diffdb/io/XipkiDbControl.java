/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.DataSourceWrapper;

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
            tblCa = "CS_CA";
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

    public String getTblCa() {
        return tblCa;
    }

    public String getTblCerthash() {
        return tblCerthash;
    }

    public String getColCaId() {
        return colCaId;
    }

    public String getColCerthash() {
        return colCerthash;
    }

    public String getCaSql() {
        return caSql;
    }

    public String getCertSql(final DataSourceWrapper datasource, final int rows) {
        return datasource.buildSelectFirstSql(certCoreSql, rows, "ID ASC");
    }

}
