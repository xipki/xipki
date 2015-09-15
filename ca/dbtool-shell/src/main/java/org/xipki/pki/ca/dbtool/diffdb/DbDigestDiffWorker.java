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

package org.xipki.pki.ca.dbtool.diffdb;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.pki.ca.dbtool.DbPortWorker;
import org.xipki.pki.ca.dbtool.DbPorter;

/**
 * @author Lijun Liao
 */

public class DbDigestDiffWorker extends DbPortWorker
{
    private static final Logger LOG = LoggerFactory.getLogger(DbDigestDiffWorker.class);
    private final boolean revokedOnly;
    private final String refDirname;
    private final DataSourceWrapper refDatasource;

    private final DataSourceWrapper dataSource;
    private final String reportDir;
    private final int numCertsPerSelect;

    public DbDigestDiffWorker(
            final DataSourceFactory dataSourceFactory,
            final PasswordResolver passwordResolver,
            final boolean revokedOnly,
            final String refDirnameOrDbConf,
            final String dbConfFile,
            final String reportDirName,
            final int numCertsPerSelect)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException
    {
        File f = new File(reportDirName);
        if(f.exists() == false)
        {
            f.mkdirs();
        }
        else
        {
            if(f.isDirectory() == false)
            {
                throw new IOException(reportDirName + " is not a folder");
            }

            if(f.canWrite() == false)
            {
                throw new IOException(reportDirName + " is not writable");
            }
        }

        String[] children = f.list();
        if(children != null && children.length > 0)
        {
            throw new IOException(reportDirName + " is not empty");
        }

        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.dataSource = dataSourceFactory.createDataSource(null, props, passwordResolver);

        this.revokedOnly = revokedOnly;
        File refFile = new File(refDirnameOrDbConf);
        if(refFile.isDirectory())
        {
            this.refDatasource = null;
            this.refDirname = refDirnameOrDbConf;
        } else
        {
            this.refDirname = null;
            Properties refProps = DbPorter.getDbConfProperties(
                    new FileInputStream(IoUtil.expandFilepath(refDirnameOrDbConf)));
            this.refDatasource = dataSourceFactory.createDataSource(
                    null, refProps, passwordResolver);
        }

        this.reportDir = reportDirName;
        this.numCertsPerSelect = numCertsPerSelect;
    }

    @Override
    public void doRun(
            final AtomicBoolean stopMe)
    throws Exception
    {
        long start = System.currentTimeMillis();

        try
        {
            DbDigestDiff diff;
            if(refDirname != null)
            {
                diff = DbDigestDiff.getInstanceForDirRef(
                    revokedOnly, refDirname, dataSource, reportDir, stopMe, numCertsPerSelect);
            } else
            {
                diff = DbDigestDiff.getInstanceForDbRef(
                    revokedOnly, refDatasource, dataSource, reportDir, stopMe, numCertsPerSelect);
            }
            diff.diff();
        } finally
        {
            try
            {
                dataSource.shutdown();
            }catch(Throwable e)
            {
                LOG.error("dataSource.shutdown()", e);
            }
            long end = System.currentTimeMillis();
            System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    }

}
