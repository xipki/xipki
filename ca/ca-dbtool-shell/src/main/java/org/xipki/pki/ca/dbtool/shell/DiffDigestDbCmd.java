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

package org.xipki.pki.ca.dbtool.shell;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.password.api.PasswordResolver;
import org.xipki.pki.ca.dbtool.diffdb.DbDigestDiffWorker;
import org.xipki.pki.ca.dbtool.port.DbPortWorker;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-db", name = "diff-digest-db",
        description = "diff digest XiPKI/EJBCA database")
public class DiffDigestDbCmd extends DbPortCmd
{
    @Option(name = "--ref-db",
            description = "database configuration file of the reference system\n"
                    + "(one of--ref-db and--ref-dir must be specified)")
    private String refDbConf;

    @Option(name = "--ref-dir",
            description = "directory of exported digest files of the reference system\n"
                    + "(one of--ref-db and--ref-dir must be specified)")
    private String refDir;

    @Option(name = "--target",
            required = true,
            description = "configuration file of the target database to be evaluated")
    private String dbconfFile;

    @Option(name = "--report-dir",
            required = true,
            description = "report directory\n"
                    + "(required)")
    private String reportDir;

    @Option(name = "--revoked-only")
    private Boolean revokedOnly = Boolean.FALSE;

    @Option(name = "-k",
            description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 1000;

    @Option(name = "--ref-threads",
            description = "number of threads to query the target database")
    private Integer numRefThreads = 5;

    @Option(name = "--target-threads",
            description = "number of threads to query the target database")
    private Integer numTargetThreads = 10;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    protected DbPortWorker getDbPortWorker()
    throws Exception
    {
        return new DbDigestDiffWorker(
                dataSourceFactory,
                passwordResolver,
                revokedOnly,
                refDir,
                refDbConf,
                dbconfFile,
                reportDir,
                numCertsPerSelect,
                numRefThreads,
                numTargetThreads);
    }

    public void setDataSourceFactory(
            final DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public void setPasswordResolver(
            final PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

}
