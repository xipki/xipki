/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ocsp.qa.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.BigIntegerRange;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.FileBigIntegerIterator;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.RangeBigIntegerIterator;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ocsp.client.api.RequestOptions;
import org.xipki.pki.ocsp.client.shell.OcspStatusCommandSupport;
import org.xipki.pki.ocsp.qa.benchmark.OcspLoadTest;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-qa", name = "benchmark-ocsp-status",
        description = "OCSP benchmark")
@Service
public class BenchmarkOcspStatusCmd extends OcspStatusCommandSupport {
    @Option(name = "--hex",
            description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial", aliases = "-s",
            description = "comma-separated serial numbers or ranges (like 1,3,6-10)\n"
                    + "(exactly one of serial, serial-file and cert must be specified)")
    private String serialNumberList;

    @Option(name = "--serial-file",
            description = "file that contains serial numbers")
    @Completion(FilePathCompleter.class)
    private String serialNumberFile;

    @Option(name = "--cert",
            multiValued = true,
            description = "certificate\n"
                    + "(multi-valued)")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Option(name = "--duration",
            description = "duration")
    private String duration = "30s";

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--analyze-response",
            description = "whether to analyze the received OCSP response")
    private Boolean analyzeResponse = Boolean.FALSE;

    @Option(name = "--url",
            required = true,
            description = "OCSP responder URL\n"
                    + "required")
    private String serverUrl;

    @Option(name = "--max-num",
            description = "maximal number of certificates to be asked\n"
                    + "0 for unlimited")
    private Integer maxCerts = 0;

    @Override
    protected Object doExecute() throws Exception {
        int ii = 0;
        if (serialNumberList != null) {
            ii++;
        }

        if (serialNumberFile != null) {
            ii++;
        }

        if (CollectionUtil.isNonEmpty(certFiles)) {
            ii++;
        }

        if (ii != 1) {
            throw new IllegalCmdParamException(
                    "exactly one of serial, serial-file and cert must be specified");
        }

        if (numThreads < 1) {
            throw new IllegalCmdParamException("invalid number of threads " + numThreads);
        }

        Iterator<BigInteger> serialNumberIterator;

        if (serialNumberFile != null) {
            serialNumberIterator = new FileBigIntegerIterator(
                    IoUtil.expandFilepath(serialNumberFile), hex, true);
        } else {
            List<BigIntegerRange> serialNumbers = new LinkedList<>();
            if (serialNumberList != null) {
                StringTokenizer st = new StringTokenizer(serialNumberList, ", ");
                while (st.hasMoreTokens()) {
                    String token = st.nextToken();
                    StringTokenizer st2 = new StringTokenizer(token, "-");
                    BigInteger from = toBigInt(st2.nextToken(), hex);
                    BigInteger to = st2.hasMoreTokens() ? toBigInt(st2.nextToken(), hex) : from;
                    serialNumbers.add(new BigIntegerRange(from, to));
                }
            } else  if (certFiles != null) {
                for (String certFile : certFiles) {
                    X509Certificate cert;
                    try {
                        cert = X509Util.parseCert(certFile);
                    } catch (Exception ex) {
                        throw new IllegalCmdParamException(
                                "invalid certificate file  '" + certFile + "'", ex);
                    }
                    BigInteger serial = cert.getSerialNumber();
                    serialNumbers.add(new BigIntegerRange(serial, serial));
                }
            }

            serialNumberIterator = new RangeBigIntegerIterator(serialNumbers, true);
        }

        try {
            StringBuilder description = new StringBuilder();
            description.append("issuer cert: ").append(issuerCertFile).append("\n");
            description.append("server URL: ").append(serverUrl.toString()).append("\n");
            description.append("maxCerts: ").append(maxCerts).append("\n");
            description.append("hash: ").append(hashAlgo);

            Certificate issuerCert = Certificate.getInstance(IoUtil.read(issuerCertFile));

            RequestOptions options = getRequestOptions();
            OcspLoadTest loadTest = new OcspLoadTest(issuerCert, serverUrl, options,
                    serialNumberIterator, maxCerts, analyzeResponse, description.toString());
            loadTest.setDuration(duration);
            loadTest.setThreads(numThreads);
            loadTest.test();
        } finally {
            if (serialNumberIterator instanceof FileBigIntegerIterator) {
                ((FileBigIntegerIterator) serialNumberIterator).close();
            }
        }

        return null;
    } // end doExecute

}
