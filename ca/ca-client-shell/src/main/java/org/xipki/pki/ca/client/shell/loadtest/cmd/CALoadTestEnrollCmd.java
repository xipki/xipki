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

package org.xipki.pki.ca.client.shell.loadtest.cmd;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.pki.ca.client.shell.loadtest.CALoadTestCmd;
import org.xipki.pki.ca.client.shell.loadtest.CALoadTestEnroll;
import org.xipki.pki.ca.client.shell.loadtest.KeyEntry;
import org.xipki.pki.ca.client.shell.loadtest.KeyEntry.DSAKeyEntry;
import org.xipki.pki.ca.client.shell.loadtest.KeyEntry.ECKeyEntry;
import org.xipki.pki.ca.client.shell.loadtest.KeyEntry.RSAKeyEntry;
import org.xipki.pki.ca.client.shell.loadtest.LoadTestEntry;
import org.xipki.pki.ca.client.shell.loadtest.LoadTestEntry.RandomDN;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-cli", name = "loadtest-enroll",
        description = "CA Client Enroll Load test")
public class CALoadTestEnrollCmd extends CALoadTestCmd
{

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "certificate profile\n"
                    + "(required)")
    private String certprofile;

    @Option(name = "--subject", aliases = "-s",
            required = true,
            description = "subject template\n"
                    + "(required)")
    private String subjectTemplate;

    @Option(name = "--random-dn",
            description = "DN name to be incremented")
    private String randomDNStr = "O";

    @Option(name = "--duration",
            description = "duration in seconds")
    private Integer durationInSecond = 30;

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--key-type",
            description = "key type to be requested")
    private String keyType = "RSA";

    @Option(name = "--key-size",
            description = "modulus length of RSA key or p length of DSA key")
    private Integer keysize = 2048;

    @Option(name = "--curve",
            description = "EC curve name or OID of EC key")
    private String curveName;

    @Option(name = "-n",
            description = "number of certificates to be requested in one request")
    private Integer n = 1;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        if (numThreads < 1)
        {
            throw new IllegalCmdParamException("invalid number of threads " + numThreads);
        }

        if (durationInSecond < 1)
        {
            throw new IllegalCmdParamException("invalid duration " + durationInSecond);
        }

        if ("EC".equalsIgnoreCase(keyType) && StringUtil.isBlank(curveName))
        {
            throw new IllegalCmdParamException("curveName is not specified");
        }

        StringBuilder description = new StringBuilder();
        description.append("subjectTemplate: ").append(subjectTemplate).append("\n");
        description.append("profile: ").append(certprofile).append("\n");
        description.append("keyType: ").append(keyType).append("\n");
        description.append("#certs/req: ").append(n).append("\n");
        description.append("unit: ").append(n).append(" certificate");
        if (n > 1)
        {
            description.append("s");
        }

        RandomDN randomDN = null;
        if (randomDNStr != null)
        {
            randomDN = RandomDN.getInstance(randomDNStr);
            if (randomDN == null)
            {
                throw new IllegalCmdParamException("invalid randomDN " + randomDNStr);
            }
        }

        KeyEntry keyEntry;
        if ("EC".equalsIgnoreCase(keyType))
        {
            keyEntry = new ECKeyEntry(curveName);
        }
        else if ("RSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new RSAKeyEntry(keysize.intValue());
        }
        else if ("DSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new DSAKeyEntry(keysize.intValue());
        }
        else
        {
            throw new IllegalCmdParamException("invalid keyType " + keyType);
        }

        LoadTestEntry loadtestEntry = new LoadTestEntry(certprofile, keyEntry,
                subjectTemplate, randomDN);
        CALoadTestEnroll loadTest = new CALoadTestEnroll(caClient, loadtestEntry,
                n, description.toString());

        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
