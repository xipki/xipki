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

package org.xipki.pki.ca.dbtool;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

abstract class AbstractOcspCertStoreDbImporter extends DbPorter
{
    protected static final String SQL_ADD_ISSUER =
        "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1S,S1K,S224S,S224K,S256S,S256K,S384S,S384K,"
        + "S512S,S512K,S1C,CERT,REV,RR,RT,RIT) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    protected static final String SQL_ADD_CERT =
        "INSERT INTO CERT (ID,IID,SN,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,RIT,PN) VALUES (?,?,?,?,?,?,?,?,?,?,?)";

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

    AbstractOcspCertStoreDbImporter(
            final DataSourceWrapper dataSource,
            final String srcDir,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception
    {
        super(dataSource, srcDir, stopMe, evaluateOnly);
    }

    protected void deleteCertGreatherThan(int id, Logger log)
    {
        deleteFromTableWithLargerId("CRAW", "CID", id, log);
        deleteFromTableWithLargerId("CHASH", "CID", id, log);
        deleteFromTableWithLargerId("CERT", "ID", id, log);
    }

    protected void dropIndexes()
    throws DataAccessException
    {
        dataSource.dropForeignKeyConstraint(null, "FK_CERT_ISSUER1", "CERT");
        dataSource.dropUniqueConstrain(null, "CONST_ISSUER_SN", "CERT");

        dataSource.dropForeignKeyConstraint(null, "FK_CHASH_CERT1", "CHASH");
        dataSource.dropForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW");

        dataSource.dropPrimaryKey(null, "PK_CERT", "CERT");
        dataSource.dropPrimaryKey(null, "PK_CRAW", "CRAW");
        dataSource.dropPrimaryKey(null, "PK_CHASH", "CHASH");
    }

    protected void recoverIndexes()
    throws DataAccessException
    {
        dataSource.addPrimaryKey(null, "PK_CERT", "CERT", "ID");
        dataSource.addPrimaryKey(null, "PK_CRAW", "CRAW", "CID");
        dataSource.addPrimaryKey(null, "PK_CHASH", "CHASH", "CID");

        dataSource.addForeignKeyConstraint(null, "FK_CERT_ISSUER1", "CERT",
                "IID", "ISSUER", "ID", "CASCADE", "NO ACTION");
        dataSource.addUniqueConstrain(null, "CONST_ISSUER_SN", "CERT", "IID", "SN");

        dataSource.addForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW", "CID", "CERT", "ID",
                "CASCADE", "NO ACTION");
        dataSource.addForeignKeyConstraint(null, "FK_CHASH_CERT1", "CHASH", "CID", "CERT", "ID",
                "CASCADE", "NO ACTION");
    }

}
