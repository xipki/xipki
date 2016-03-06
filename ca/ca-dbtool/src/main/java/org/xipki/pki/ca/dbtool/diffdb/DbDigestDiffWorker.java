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
import java.util.Properties;
import java.util.Set;

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
import org.xipki.pki.ca.dbtool.port.DbPortWorker;
import org.xipki.pki.ca.dbtool.port.DbPorter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbDigestDiffWorker extends DbPortWorker {

    private static final Logger LOG = LoggerFactory.getLogger(DbDigestDiffWorker.class);

    private final boolean revokedOnly;

    private final String refDirname;

    private final DataSourceWrapper refDatasource;

    private final Set<byte[]> includeCaCerts;

    private final DataSourceWrapper datasource;

    private final String reportDir;

    private final int numCertsPerSelect;

    private final NumThreads numThreads;

    public DbDigestDiffWorker(
            final DataSourceFactory datasourceFactory,
            final PasswordResolver passwordResolver,
            final boolean revokedOnly,
            final String refDirname,
            final String refDbConfFile,
            final String dbConfFile,
            final String reportDirName,
            final int numCertsPerSelect,
            final NumThreads numThreads,
            final Set<byte[]> includeCaCerts)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException {
        ParamUtil.requireNonNull("datasourceFactory", datasourceFactory);
        this.reportDir = ParamUtil.requireNonBlank("reportDirName", reportDirName);
        this.numThreads = ParamUtil.requireNonNull("numThreads", numThreads);

        this.numCertsPerSelect = numCertsPerSelect;

        boolean validRef = false;
        if (refDirname == null) {
            validRef = (refDbConfFile != null);
        } else {
            validRef = (refDbConfFile == null);
        }

        if (!validRef) {
            throw new IllegalArgumentException(
                    "Exactly one of refDirname and refDbConffile must be not null");
        }

        this.includeCaCerts = includeCaCerts;

        File file = new File(reportDirName);
        if (!file.exists()) {
            file.mkdirs();
        } else {
            if (!file.isDirectory()) {
                throw new IOException(reportDirName + " is not a folder");
            }

            if (!file.canWrite()) {
                throw new IOException(reportDirName + " is not writable");
            }
        }

        String[] children = file.list();
        if (children != null && children.length > 0) {
            throw new IOException(reportDirName + " is not empty");
        }

        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.datasource = datasourceFactory.createDataSource(null, props, passwordResolver);

        this.revokedOnly = revokedOnly;
        if (refDirname != null) {
            this.refDirname = refDirname;
            this.refDatasource = null;
        } else {
            this.refDirname = null;
            Properties refProps = DbPorter.getDbConfProperties(
                    new FileInputStream(IoUtil.expandFilepath(refDbConfFile)));
            this.refDatasource = datasourceFactory.createDataSource(
                    null, refProps, passwordResolver);
        }
    } // constructor DbDigestDiffWorker

    @Override
    public void doRun()
    throws Exception {
        long start = System.currentTimeMillis();

        try {
            DbDigestDiff diff;
            if (refDirname != null) {
                diff = DbDigestDiff.getInstanceForDirRef(refDirname, datasource, reportDir,
                        revokedOnly, stopMe, numCertsPerSelect, numThreads);
            } else {
                diff = DbDigestDiff.getInstanceForDbRef(refDatasource, datasource, reportDir,
                        revokedOnly, stopMe, numCertsPerSelect, numThreads);
            }
            diff.setIncludeCaCerts(includeCaCerts);
            diff.diff();
        } finally {
            if (refDatasource != null) {
                try {
                    refDatasource.shutdown();
                } catch (Throwable th) {
                    LOG.error("refDatasource.shutdown()", th);
                }
            }

            try {
                datasource.shutdown();
            } catch (Throwable th) {
                LOG.error("datasource.shutdown()", th);
            }
            long end = System.currentTimeMillis();
            System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    } // method doRun

}
