/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.client.shell.loadtest;

import java.io.FileInputStream;
import java.util.Properties;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ca.client.shell.ClientCommand;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "loadtest-revoke", description="CA Client Revoke Load test")
public class CALoadTestRevokeCommand extends ClientCommand
{
    @Option(name = "-cacert",
            required = true,
            description = "CA Certificate file")
    protected String caCertFile;

    @Option(name = "-duration",
            required = false,
            description = "Required. Maximal duration in seconds")
    protected Integer durationInSecond = 30;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads")
    protected Integer numThreads = 5;

    @Option(name = "-cadb",
            required = true,
            description = "CA database configuration file")
    protected String caDbConfFile;

    @Option(name = "-maxCerts",
            required = false,
            description = "maximal number of certificates to be revoked. 0 for unlimited")
    protected Integer maxCerts = 0;

    @Option(name = "-n",
            description = "Number of certificates to be revoked in one request",
            required = false)
    protected Integer n = 1;

    private DataSourceFactory dataSourceFactory;
    private SecurityFactory securityFactory;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads < 1)
        {
            err("Invalid number of threads " + numThreads);
            return null;
        }

        if(durationInSecond < 1)
        {
            err("Invalid duration " + durationInSecond);
            return null;
        }

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:         ").append(numThreads).append("\n");
        startMsg.append("Max. Duration:   ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("cacert:          ").append(caCertFile).append("\n");
        startMsg.append("cadb:            ").append(caDbConfFile).append("\n");
        startMsg.append("maxCerts:        ").append(maxCerts).append("\n");
        startMsg.append("#Certs/Request:  ").append(n).append("\n");
        startMsg.append("Unit:            ").append(n).append(" certificate");
        if(n > 1)
        {
            startMsg.append("s");
        }
        startMsg.append("\n");
        out(startMsg.toString());

        Certificate caCert = Certificate.getInstance(IoCertUtil.read(caCertFile));
        Properties props = new Properties();
        props.load(new FileInputStream(IoCertUtil.expandFilepath(caDbConfFile)));
        props.setProperty("autoCommit", "false");
        props.setProperty("readOnly", "true");
        props.setProperty("maximumPoolSize", "1");
        props.setProperty("minimumIdle", "1");

        DataSourceWrapper caDataSource = dataSourceFactory.createDataSource(props, securityFactory.getPasswordResolver());
        try
        {
            CALoadTestRevoke loadTest = new CALoadTestRevoke(raWorker, caCert, caDataSource, maxCerts, n);

            loadTest.setDuration(durationInSecond);
            loadTest.setThreads(numThreads);
            loadTest.test();
        }finally
        {
            caDataSource.shutdown();
        }

        return null;
    }

    public void setDataSourceFactory(DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }
}
