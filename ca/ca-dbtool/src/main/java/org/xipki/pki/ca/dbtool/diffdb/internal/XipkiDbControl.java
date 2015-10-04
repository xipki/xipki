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

package org.xipki.pki.ca.dbtool.diffdb.internal;

/**
 * @author Lijun Liao
 */

public class XipkiDbControl {

    private final String tblCa;
    private final String tblCerthash;
    private final String colCaId;
    private final String colCertId;
    private final String colCerthash;
    private final String colRevoked;
    private final String colRevReason;
    private final String colRevTime;
    private final String colRevInvTime;
    private final String colSerialNumber;

    private final String caSql;
    private final String certSql;

    public XipkiDbControl(
            final DbSchemaType dbSchemaType) {
        if (dbSchemaType == DbSchemaType.XIPKI_CA_v1
                || dbSchemaType == DbSchemaType.XIPKI_OCSP_v1) {
            if (dbSchemaType == DbSchemaType.XIPKI_CA_v1) { // CA
                tblCa = "CAINFO";
                tblCerthash = "RAWCERT";
                colCaId = "CAINFO_ID";
            } else { // OCSP
                tblCa = "ISSUER";
                tblCerthash = "CERTHASH";
                colCaId = "ISSUER_ID";
            }

            colCerthash = "SHA1_FP";
            colCertId = "CERT_ID";
            colRevInvTime = "REV_INVALIDITY_TIME";
            colRevoked = "REVOKED";
            colRevReason = "REV_REASON";
            colRevTime = "REV_TIME";
            colSerialNumber = "SERIAL";
        } else if (dbSchemaType == DbSchemaType.XIPKI_CA_v2
                || dbSchemaType == DbSchemaType.XIPKI_OCSP_v2) {
            if (dbSchemaType == DbSchemaType.XIPKI_CA_v2) { // CA
                tblCa = "CS_CA";
                tblCerthash = "CRAW";
                colCaId = "CA_ID";
                colCerthash = "SHA1";
            } else { // OCSP
                tblCa = "ISSUER";
                tblCerthash = "CHASH";
                colCaId = "IID";
                colCerthash = "S1";
            }

            colCertId = "CID";
            colRevInvTime = "RIT";
            colRevoked = "REV";
            colRevReason = "RR";
            colRevTime = "RT";
            colSerialNumber = "SN";
        } else {
            throw new RuntimeException("unsupported DbSchemaType " + dbSchemaType);
        }

        // CA SQL
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT ID, CERT FROM ").append(tblCa);
        this.caSql = sb.toString();

        // CERT SQL
        sb.delete(0, sb.length());
        sb.append("SELECT ID,");
        sb.append(colCaId).append(",");
        sb.append(colSerialNumber).append(",");
        sb.append(colRevoked).append(",");
        sb.append(colRevReason).append(",");
        sb.append(colRevTime).append(",");
        sb.append(colRevInvTime).append(",");
        sb.append(colCerthash);
        sb.append(" FROM CERT INNER JOIN ").append(tblCerthash);
        sb.append(" ON CERT.ID>=? AND CERT.ID<? AND CERT.ID=");
        sb.append(tblCerthash).append(".").append(colCertId);
        sb.append(" ORDER BY CERT.ID ASC");
        this.certSql = sb.toString();
    }

    public String getTblCa() {
        return tblCa;
    }

    public String getTblCerthash() {
        return tblCerthash;
    }

    public String getColCaId() {
        return colCaId;
    }

    public String getColCertId() {
        return colCertId;
    }

    public String getColCerthash() {
        return colCerthash;
    }

    public String getColRevoked() {
        return colRevoked;
    }

    public String getColRevReason() {
        return colRevReason;
    }

    public String getColRevTime() {
        return colRevTime;
    }

    public String getColRevInvTime() {
        return colRevInvTime;
    }

    public String getColSerialNumber() {
        return colSerialNumber;
    }

    public String getCaSql() {
        return caSql;
    }

    public String getCertSql() {
        return certSql;
    }

}
