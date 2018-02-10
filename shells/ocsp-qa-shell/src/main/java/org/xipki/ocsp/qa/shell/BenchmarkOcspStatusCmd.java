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

package org.xipki.ocsp.qa.shell;

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
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.shell.OcspStatusAction;
import org.xipki.ocsp.qa.benchmark.OcspBenchmark;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xiqa", name = "benchmark-ocsp-status",
        description = "OCSP benchmark")
@Service
public class BenchmarkOcspStatusCmd extends OcspStatusAction {
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

    @Option(name = "--cert", multiValued = true,
            description = "certificate\n(multi-valued)")
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

    @Option(name = "--url", required = true,
            description = "OCSP responder URL\n(required)")
    private String serverUrl;

    @Option(name = "--max-num",
            description = "maximal number of OCSP queries\n0 for unlimited")
    private Integer maxRequests = 0;

    @Option(name = "--queue-size",
            description = "Number of maximal HTTP requests in the sending queue\n"
                    + "0 for implemention default")
    private Integer queueSize = 0;

    @Override
    protected Object execute0() throws Exception {
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
            String description = StringUtil.concatObjects("issuer cert: ", issuerCertFile,
                    "\nserver URL: ",serverUrl, "\nmaxRequest: ", maxRequests,
                    "\nhash: ", hashAlgo);

            Certificate issuerCert = Certificate.getInstance(IoUtil.read(issuerCertFile));

            RequestOptions options = getRequestOptions();
            OcspBenchmark loadTest = new OcspBenchmark(issuerCert, serverUrl, options,
                    serialNumberIterator, maxRequests, analyzeResponse, queueSize,
                    description.toString());
            loadTest.setDuration(duration);
            loadTest.setThreads(numThreads);
            loadTest.test();
        } finally {
            if (serialNumberIterator instanceof FileBigIntegerIterator) {
                ((FileBigIntegerIterator) serialNumberIterator).close();
            }
        }

        return null;
    } // end execute0

}
