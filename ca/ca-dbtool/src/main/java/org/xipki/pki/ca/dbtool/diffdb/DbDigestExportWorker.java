/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.dbtool.diffdb;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.util.Properties;

import javax.xml.bind.JAXBException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.api.DataSourceFactory;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.pki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.pki.ca.dbtool.port.DbPortWorker;
import org.xipki.pki.ca.dbtool.port.DbPorter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbDigestExportWorker extends DbPortWorker {

    private static final Logger LOG = LoggerFactory.getLogger(DbDigestExportWorker.class);

    private final DataSourceWrapper datasource;

    private final String destFolder;

    private final int numCertsPerSelect;

    private final int numThreads;

    public DbDigestExportWorker(
            final DataSourceFactory datasourceFactory,
            final PasswordResolver passwordResolver,
            final String dbConfFile,
            final String destFolder,
            final int numCertsPerSelect,
            final int numThreads)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException {
        ParamUtil.requireNonNull("datasourceFactory", datasourceFactory);
        ParamUtil.requireNonNull("dbConfFile", dbConfFile);
        this.destFolder = ParamUtil.requireNonNull("destFolder", destFolder);

        File file = new File(destFolder);
        if (!file.exists()) {
            file.mkdirs();
        } else {
            if (!file.isDirectory()) {
                throw new IOException(destFolder + " is not a folder");
            }

            if (!file.canWrite()) {
                throw new IOException(destFolder + " is not writable");
            }
        }

        String[] children = file.list();
        if (children != null && children.length > 0) {
            throw new IOException(destFolder + " is not empty");
        }

        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props,
                passwordResolver);
        this.numCertsPerSelect = numCertsPerSelect;
        this.numThreads = numThreads;
    } // constructor

    @Override
    public void doRun()
    throws Exception {
        long start = System.currentTimeMillis();

        try {
            DbSchemaType dbSchemaType = detectDbSchemaType(datasource);
            System.out.println("database schema: " + dbSchemaType);
            DbDigestExporter digester;
            if (dbSchemaType == DbSchemaType.EJBCA_CA_v3) {
                digester = new EjbcaDigestExporter(datasource, destFolder, stopMe,
                        numCertsPerSelect, dbSchemaType, numThreads);
            } else {
                digester = new XipkiDigestExporter(datasource, destFolder, stopMe,
                        numCertsPerSelect, dbSchemaType, numThreads);
            }
            digester.digest();
        } finally {
            try {
                datasource.shutdown();
            } catch (Throwable th) {
                LOG.error("datasource.shutdown()", th);
            }
            long end = System.currentTimeMillis();
            System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    } // method doRun

    public static DbSchemaType detectDbSchemaType(
            final DataSourceWrapper datasource)
    throws DataAccessException {
        Connection conn = datasource.getConnection();
        try {
            if (datasource.tableExists(conn, "CAINFO")
                    && datasource.tableExists(conn, "RAWCERT")) {
                return DbSchemaType.XIPKI_CA_v1;
            } else if (datasource.tableExists(conn, "ISSUER")
                    && datasource.tableExists(conn, "CERTHASH")) {
                return DbSchemaType.XIPKI_OCSP_v1;
            } else if (datasource.tableExists(conn, "CS_CA")
                    && datasource.tableExists(conn, "CRAW")) {
                return DbSchemaType.XIPKI_CA_v2;
            } else if (datasource.tableExists(conn, "ISSUER")
                    && datasource.tableExists(conn, "CHASH")) {
                return DbSchemaType.XIPKI_OCSP_v2;
            } else if (datasource.tableExists(conn, "CAData")
                    && datasource.tableExists(conn, "CertificateData")) {
                return DbSchemaType.EJBCA_CA_v3;
            } else {
                throw new IllegalArgumentException("unknown database schema");
            }
        } finally {
            datasource.returnConnection(conn);
        }
    }

}
