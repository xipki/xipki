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

package org.xipki.ca.client.shell.loadtest;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Properties;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.FileBigIntegerIterator;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.SecurityFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xiqa", name = "cmp-benchmark-revoke",
        description = "CA client revoke load test")
@Service
public class CaLoadTestRevokeCmd extends CaLoadTestAction {

    @Option(name = "--issuer",
            required = true,
            description = "issuer certificate file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String issuerCertFile;

    @Option(name = "--duration",
            description = "maximal duration")
    private String duration = "30s";

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--ca-db",
            description = "CA database configuration file\n"
                    + "(exactly one of ca-db and serial-file must be specified)")
    @Completion(FilePathCompleter.class)
    private String caDbConfFile;

    @Option(name = "--hex",
            description = "serial number without prefix in the serial-file is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial-file",
            description = "file that contains serial numbers")
    @Completion(FilePathCompleter.class)
    private String serialNumberFile;

    @Option(name = "--max-num",
            description = "maximal number of certificates to be revoked\n"
                    + "0 for unlimited")
    private Integer maxCerts = 0;

    @Option(name = "-n",
            description = "number of certificates to be revoked in one request")
    private Integer num = 1;

    @Reference
    private SecurityFactory securityFactory;

    @Override
    protected Object execute0() throws Exception {
        if (numThreads < 1) {
            throw new IllegalCmdParamException("invalid number of threads " + numThreads);
        }

        if (!(serialNumberFile == null ^ caDbConfFile == null)) {
            throw new IllegalCmdParamException(
                    "exactly one of ca-db and serial-file must be specified");
        }

        StringBuilder description = new StringBuilder(200);
        description.append("issuer: ").append(issuerCertFile).append("\n");
        description.append("cadb: ").append(caDbConfFile).append("\n");
        description.append("serialNumberFile: ").append(serialNumberFile).append("\n");
        description.append("maxCerts: ").append(maxCerts).append("\n");
        description.append("#certs/req: ").append(num).append("\n");
        description.append("unit: ").append(num).append(" certificate");
        if (num > 1) {
            description.append("s");
        }
        description.append("\n");

        Certificate caCert = Certificate.getInstance(IoUtil.read(issuerCertFile));
        Properties props = new Properties();
        props.load(new FileInputStream(IoUtil.expandFilepath(caDbConfFile)));
        props.setProperty("autoCommit", "false");
        props.setProperty("readOnly", "true");
        props.setProperty("maximumPoolSize", "1");
        props.setProperty("minimumIdle", "1");

        DataSourceWrapper caDataSource = null;
        Iterator<BigInteger> serialNumberIterator;
        if (caDbConfFile != null) {
            caDataSource = new DataSourceFactory().createDataSource(
                    "ds-" + caDbConfFile, props, securityFactory.getPasswordResolver());
            serialNumberIterator = new DbGoodCertSerialIterator(caCert, caDataSource);
        } else {
            serialNumberIterator = new FileBigIntegerIterator(serialNumberFile, hex, false);
        }

        try {
            CaLoadTestRevoke loadTest = new CaLoadTestRevoke(
                    caClient, caCert, serialNumberIterator, maxCerts, num, description.toString());

            loadTest.setDuration(duration);
            loadTest.setThreads(numThreads);
            loadTest.test();
        } finally {
            if (caDataSource != null) {
                caDataSource.close();
            }

            if (serialNumberIterator instanceof FileBigIntegerIterator) {
                ((FileBigIntegerIterator) serialNumberIterator).close();
            }
        }

        return null;
    } // method execute0

}
