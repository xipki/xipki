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

package org.xipki.ca.client.shell.loadtest;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.client.shell.ClientCommand;
import org.xipki.ca.client.shell.loadtest.KeyEntry.DSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.ECKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.RSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.LoadTestEntry.RandomDN;
import org.xipki.common.AbstractLoadTest;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-client", name = "loadtest-enroll", description="CA Client Enroll Load test")
public class CALoadTestEnrollCommand extends ClientCommand
{

    @Option(name = "-profile",
            required = true,
            description = "Required. Certificate profile")
    protected String certprofile;

    @Option(name = "-subject",
            required = true,
            description = "Required. Subject template")
    protected String subjectTemplate;

    @Option(name = "-randomDN",
            required = false,
            description = "DN name to be incremented, valid values are\n"
                    + "GIVENNAME, SURNAME, STREET, POSTALCODE, O, OU and CN")
    protected String randomDNStr = "O";

    @Option(name = "-duration",
            required = false,
            description = "Required. Duration in seconds")
    protected Integer durationInSecond = 30;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads")
    protected Integer numThreads = 5;

    @Option(name="-keyType",
            required = false,
            description = "Key type to be requested. Valid values are RSA, EC and DSA")
    private String keyType = "RSA";

    @Option(name="-keysize",
            required = false,
            description = "Modulus length of RSA key or p length of DSA key")
    private Integer keysize = 2048;

    @Option(name = "-curve",
            description = "EC curve name or OID of EC key",
            required = false)
    protected String curveName = "brainpoolp256r1";

    @Option(name = "-n",
            description = "Number of certificates to be requested in one request",
            required = false)
    protected Integer n = 1;

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
        startMsg.append("Duration:        ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("SubjectTemplate: ").append(subjectTemplate).append("\n");
        startMsg.append("Profile:         ").append(certprofile).append("\n");
        startMsg.append("KeyType:         ").append(keyType).append("\n");
        startMsg.append("#Certs/Request:  ").append(n).append("\n");
        startMsg.append("Unit:            ").append(n).append(" certificate");
        if(n > 1)
        {
            startMsg.append("s");
        }
        startMsg.append("\n");
        out(startMsg.toString());

        RandomDN randomDN = null;
        if(randomDNStr != null)
        {
            randomDN = RandomDN.getInstance(randomDNStr);
            if(randomDN == null)
            {
                err("Invalid randomDN " + randomDNStr);
                return null;
            }
        }

        KeyEntry keyEntry;
        if("EC".equalsIgnoreCase(keyType))
        {
            keyEntry = new ECKeyEntry(curveName);
        }
        else if("RSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new RSAKeyEntry(keysize.intValue());
        }
        else if("DSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new DSAKeyEntry(keysize.intValue());
        }
        else
        {
            err("Invalid keyType " + keyType);
            return null;
        }

        LoadTestEntry loadtestEntry = new LoadTestEntry(certprofile, keyEntry, subjectTemplate, randomDN);
        CALoadTestEnroll loadTest = new CALoadTestEnroll(raWorker, loadtestEntry, n);

        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
