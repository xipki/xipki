/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.dbtool.diffdb;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

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

    public DbDigestExportWorker(DataSourceFactory datasourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, String destFolder,
            int numCertsPerSelect, int numThreads)
            throws DataAccessException, PasswordResolverException, IOException {
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
    protected void run0() throws Exception {
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
                        numCertsPerSelect, dbSchemaType);
            }
            digester.digest();
        } finally {
            try {
                datasource.close();
            } catch (Throwable th) {
                LOG.error("datasource.close()", th);
            }
            long end = System.currentTimeMillis();
            System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    } // method run0

    public static DbSchemaType detectDbSchemaType(DataSourceWrapper datasource)
            throws DataAccessException {
        Connection conn = datasource.getConnection();
        try {
            if (datasource.tableExists(conn, "CA")
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
