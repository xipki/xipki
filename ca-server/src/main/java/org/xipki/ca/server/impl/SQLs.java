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
