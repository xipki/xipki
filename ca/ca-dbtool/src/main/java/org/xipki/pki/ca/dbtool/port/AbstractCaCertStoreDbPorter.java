/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.port;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

class AbstractCaCertStoreDbPorter extends DbPorter {

    private static final String CRLS_DIRNAME = "crls";

    private static final String CRLS_MANIFEST_FILENAME = "crls-manifest";

    private static final String USERS_DIRNAME = "users";

    private static final String USERS_MANIFEST_FILENAME = "users-manifest";

    protected final String crlsDir;

    protected final String crlsListFile;

    protected final String usersDir;

    protected final String usersListFile;

    AbstractCaCertStoreDbPorter(
            final DataSourceWrapper dataSource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws DataAccessException {
        super(dataSource, baseDir, stopMe, evaluateOnly);

        this.crlsDir = this.baseDir + File.separator + CRLS_DIRNAME;
        this.crlsListFile = this.baseDir + File.separator + CRLS_MANIFEST_FILENAME;

        this.usersDir = this.baseDir + File.separator + USERS_DIRNAME;
        this.usersListFile = this.baseDir + File.separator + USERS_MANIFEST_FILENAME;
    }

}
