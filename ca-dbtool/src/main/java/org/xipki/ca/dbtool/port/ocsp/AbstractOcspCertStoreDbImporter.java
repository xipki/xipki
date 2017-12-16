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

package org.xipki.ca.dbtool.port.ocsp;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class AbstractOcspCertStoreDbImporter extends DbPorter {

    protected static final String MSG_CERTS_FINISHED = "certs.finished";

    protected static final String SQL_ADD_ISSUER =
        "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,REV,RR,RT,RIT,CERT) "
        + "VALUES (?,?,?,?,?,?,?,?,?,?)";

    protected static final String SQL_ADD_CERT =
        "INSERT INTO CERT (ID,IID,SN,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,RIT,PN)"
        + " VALUES (?,?,?,?,?,?,?,?,?,?,?)";

    protected static final String SQL_DEL_CERT =
        "DELETE FROM CERT WHERE ID>?";

    protected static final String SQL_ADD_CHASH =
        "INSERT INTO CHASH (CID,S1,S224,S256,S384,S512) VALUES (?,?,?,?,?,?)";

    protected static final String SQL_DEL_CHASH =
        "DELETE FROM CHASH WHERE ID>?";

    protected static final String SQL_ADD_CRAW =
        "INSERT INTO CRAW (CID,SUBJECT,CERT) VALUES (?,?,?)";

    protected static final String SQL_DEL_CRAW =
        "DELETE FROM CRAW WHERE ID>?";

    AbstractOcspCertStoreDbImporter(final DataSourceWrapper datasource, final String srcDir,
            final AtomicBoolean stopMe, final boolean evaluateOnly) throws Exception {
        super(datasource, srcDir, stopMe, evaluateOnly);
    }

    protected String sha1(final byte[] data) {
        return HashAlgoType.SHA1.base64Hash(data);
    }

    protected String sha224(final byte[] data) {
        return HashAlgoType.SHA224.base64Hash(data);
    }

    protected String sha256(final byte[] data) {
        return HashAlgoType.SHA256.base64Hash(data);
    }

    protected String sha384(final byte[] data) {
        return HashAlgoType.SHA384.base64Hash(data);
    }

    protected String sha512(final byte[] data) {
        return HashAlgoType.SHA512.base64Hash(data);
    }

    protected void deleteCertGreatherThan(final long id, final Logger log) {
        deleteFromTableWithLargerId("CRAW", "CID", id, log);
        deleteFromTableWithLargerId("CHASH", "CID", id, log);
        deleteFromTableWithLargerId("CERT", "ID", id, log);
    }

    protected void dropIndexes() throws DataAccessException {
        System.out.println("dropping indexes");
        long start = System.currentTimeMillis();

        datasource.dropForeignKeyConstraint(null, "FK_CERT_ISSUER1", "CERT");
        datasource.dropUniqueConstrain(null, "CONST_ISSUER_SN", "CERT");

        datasource.dropForeignKeyConstraint(null, "FK_CHASH_CERT1", "CHASH");
        datasource.dropForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW");

        datasource.dropPrimaryKey(null, "PK_CERT", "CERT");
        datasource.dropPrimaryKey(null, "PK_CRAW", "CRAW");
        datasource.dropPrimaryKey(null, "PK_CHASH", "CHASH");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" dropped indexes in " + StringUtil.formatTime(duration, false));
    }

    protected void recoverIndexes() throws DataAccessException {
        System.out.println("recovering indexes");
        long start = System.currentTimeMillis();

        datasource.addPrimaryKey(null, "PK_CERT", "CERT", "ID");
        datasource.addPrimaryKey(null, "PK_CRAW", "CRAW", "CID");
        datasource.addPrimaryKey(null, "PK_CHASH", "CHASH", "CID");

        datasource.addForeignKeyConstraint(null, "FK_CERT_ISSUER1", "CERT",
                "IID", "ISSUER", "ID", "CASCADE", "NO ACTION");
        datasource.addUniqueConstrain(null, "CONST_ISSUER_SN", "CERT", "IID", "SN");

        datasource.addForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW", "CID", "CERT", "ID",
                "CASCADE", "NO ACTION");
        datasource.addForeignKeyConstraint(null, "FK_CHASH_CERT1", "CHASH", "CID", "CERT", "ID",
                "CASCADE", "NO ACTION");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" recovered indexes in " + StringUtil.formatTime(duration, false));
    }

}
