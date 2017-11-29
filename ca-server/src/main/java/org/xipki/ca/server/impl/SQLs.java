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

package org.xipki.ca.server.impl;

import org.xipki.datasource.DataSourceWrapper;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
class SQLs {

    final String sqlSelectProfileId;
    final String sqlSelectProfile;
    final String sqlSelectPublisherId;
    final String sqlSelectPublisher;
    final String sqlSelectRequestorId;
    final String sqlSelectRequestor;
    final String sqlSelectCrlSigner;
    final String sqlSelectCmpControl;
    final String sqlSelectResponder;
    final String sqlSelectCaId;
    final String sqlSelectCa;
    final String sqlNextSelectCrlNo;
    final String sqlSelectScep;
    final String sqlSelectSystemEvent;
    final String sqlSelectUserId;
    final String sqlSelectUser;

    SQLs(final DataSourceWrapper datasource) {
        this.sqlSelectProfileId = datasource.buildSelectFirstSql(1,
                "ID FROM PROFILE WHERE NAME=?");

        this.sqlSelectProfile = datasource.buildSelectFirstSql(1,
                "ID,TYPE,CONF FROM PROFILE WHERE NAME=?");

        this.sqlSelectPublisherId = datasource.buildSelectFirstSql(1,
                "ID FROM PUBLISHER WHERE NAME=?");

        this.sqlSelectPublisher = datasource.buildSelectFirstSql(1,
                "ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?");

        this.sqlSelectRequestorId = datasource.buildSelectFirstSql(1,
                "ID FROM REQUESTOR WHERE NAME=?");

        this.sqlSelectRequestor = datasource.buildSelectFirstSql(1,
                "ID,CERT FROM REQUESTOR WHERE NAME=?");

        this.sqlSelectCrlSigner = datasource.buildSelectFirstSql(1,
                "SIGNER_TYPE,SIGNER_CERT,CRL_CONTROL,SIGNER_CONF FROM CRLSIGNER WHERE NAME=?");

        this.sqlSelectCmpControl = datasource.buildSelectFirstSql(1,
                "CONF FROM CMPCONTROL WHERE NAME=?");

        this.sqlSelectResponder = datasource.buildSelectFirstSql(1,
                "TYPE,CERT,CONF FROM RESPONDER WHERE NAME=?");

        this.sqlSelectCaId = datasource.buildSelectFirstSql(1,
                "ID FROM CA WHERE NAME=?");

        this.sqlSelectCa = datasource.buildSelectFirstSql(1,
                "ID,ART,SN_SIZE,NEXT_CRLNO,STATUS,MAX_VALIDITY,CERT,SIGNER_TYPE"
                + ",CRLSIGNER_NAME,RESPONDER_NAME,CMPCONTROL_NAME,DUPLICATE_KEY"
                + ",DUPLICATE_SUBJECT,SAVE_REQ,PERMISSION,NUM_CRLS,KEEP_EXPIRED_CERT_DAYS"
                + ",EXPIRATION_PERIOD,REV,RR,RT,RIT,VALIDITY_MODE,CRL_URIS,DELTACRL_URIS"
                + ",OCSP_URIS,CACERT_URIS,EXTRA_CONTROL,SIGNER_CONF FROM CA WHERE NAME=?");

        this.sqlNextSelectCrlNo = datasource.buildSelectFirstSql(1,
                "NEXT_CRLNO FROM CA WHERE ID=?");

        this.sqlSelectScep = datasource.buildSelectFirstSql(1,
                "ACTIVE,CA_ID,PROFILES,CONTROL,RESPONDER_TYPE,RESPONDER_CERT,RESPONDER_CONF"
                + " FROM SCEP WHERE NAME=?");

        this.sqlSelectSystemEvent = datasource.buildSelectFirstSql(1,
                "EVENT_TIME,EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?");

        this.sqlSelectUserId = datasource.buildSelectFirstSql(1,
                "ID FROM TUSER WHERE NAME=?");

        this.sqlSelectUser = datasource.buildSelectFirstSql(1,
                "ID,ACTIVE,PASSWORD FROM TUSER WHERE ID=?");

    }

}
