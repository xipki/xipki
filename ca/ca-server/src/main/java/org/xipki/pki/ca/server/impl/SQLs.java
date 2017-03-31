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

package org.xipki.pki.ca.server.impl;

import org.xipki.commons.datasource.DataSourceWrapper;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
class SQLs {

    final String sqlSelectCertprofile;
    final String sqlSelectPublisher;
    final String sqlSelectRequestor;
    final String sqlSelectCrlSigner;
    final String sqlSelectCmpControl;
    final String sqlSelectResponder;
    final String sqlSelectCa;
    final String sqlSelectScep;
    final String sqlGetUserId;

    final String sqlGetUser;

    SQLs(final DataSourceWrapper datasource) {
        this.sqlSelectCertprofile = datasource.buildSelectFirstSql(
                "ID,TYPE,CONF FROM PROFILE WHERE NAME=?", 1);

        this.sqlSelectPublisher = datasource.buildSelectFirstSql(
                "ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?", 1);

        this.sqlSelectRequestor = datasource.buildSelectFirstSql(
                "ID,CERT FROM REQUESTOR WHERE NAME=?", 1);

        this.sqlSelectCrlSigner = datasource.buildSelectFirstSql(
                "SIGNER_TYPE,SIGNER_CERT,CRL_CONTROL,SIGNER_CONF FROM CRLSIGNER WHERE NAME=?",
                1);

        this.sqlSelectCmpControl = datasource.buildSelectFirstSql(
                "CONF FROM CMPCONTROL WHERE NAME=?", 1);

        this.sqlSelectResponder = datasource.buildSelectFirstSql(
                "TYPE,CERT,CONF FROM RESPONDER WHERE NAME=?", 1);

        this.sqlSelectCa = datasource.buildSelectFirstSql(
                "ID,NAME,ART,SN_SIZE,NEXT_CRLNO,STATUS,MAX_VALIDITY,CERT,SIGNER_TYPE"
                + ",CRLSIGNER_NAME,RESPONDER_NAME,CMPCONTROL_NAME,DUPLICATE_KEY"
                + ",DUPLICATE_SUBJECT,SAVE_REQ,PERMISSIONS,NUM_CRLS,KEEP_EXPIRED_CERT_DAYS"
                + ",EXPIRATION_PERIOD,REV,RR,RT,RIT,VALIDITY_MODE,CRL_URIS,DELTACRL_URIS"
                + ",OCSP_URIS,CACERT_URIS,EXTRA_CONTROL,SIGNER_CONF FROM CA WHERE NAME=?", 1);

        this.sqlSelectScep = datasource.buildSelectFirstSql(
                "ACTIVE,CA_ID,PROFILES,CONTROL,RESPONDER_TYPE,RESPONDER_CERT,RESPONDER_CONF"
                + " FROM SCEP WHERE NAME=?", 1);

        this.sqlGetUserId = datasource.buildSelectFirstSql("ID FROM USERNAME WHERE NAME=?", 1);

        this.sqlGetUser = datasource.buildSelectFirstSql(
                "ID,ACTIVE,PASSWORD FROM USERNAME WHERE ID=?", 1);
    }

}
