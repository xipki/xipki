/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

import java.io.FileInputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

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

    @Option(name = "-excludeSerials",
            required = false,
            description = "Comma-separated serial numbers to be ignored")
    protected String excludeSerials;

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
        startMsg.append("excludeSerials:  ").append(excludeSerials).append("\n");
        out(startMsg.toString());

        Certificate caCert = Certificate.getInstance(IoCertUtil.read(caCertFile));
        Properties props = new Properties();
        props.load(new FileInputStream(IoCertUtil.expandFilepath(caDbConfFile)));
        props.setProperty("autoCommit", "false");
        props.setProperty("readOnly", "true");
        props.setProperty("maximumPoolSize", "1");
        props.setProperty("minimumIdle", "1");

        Set<Long> excludeSerialsSet = new HashSet<>();
        if(excludeSerials != null && excludeSerials.isEmpty() == false)
        {
            StringTokenizer st = new StringTokenizer(excludeSerials, ",");
            excludeSerialsSet.add(Long.parseLong(st.nextToken()));
        }

        DataSourceWrapper caDataSource = dataSourceFactory.createDataSource(props, securityFactory.getPasswordResolver());
        try
        {
            CALoadTestRevoke loadTest = new CALoadTestRevoke(raWorker, caCert, caDataSource, excludeSerialsSet);

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
