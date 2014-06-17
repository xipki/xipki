/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ocsp.client.shell.loadtest;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.ClientRequestOptions;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ocsp", name = "status-loadtest", description="OCSP Load test")
public class OCSPStatusLoadTestCommand extends OsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";
    @Option(name = "-url",
            description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

    @Option(name = "-cacert",
            required = true, description = "Required. CA certificate file")
    protected String            caCertFile;

    @Option(name = "-serial",
            required = true,
            description = "Required. Serial numbers. Comma-seperated serial numbers or ranges")
    protected String           serialNumbers;

    @Option(name = "-duration",
            required = true,
            description = "Required. Duration in seconds")
    protected int              durationInSecond;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads, the default is 5")
    protected Integer          numThreads;

    @Option(name = "-nonce",
            description = "Use nonce")
    protected Boolean            useNonce;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

    @Option(name = "-sigalgs",
            required = false, description = "comma-seperated preferred signature algorithms")
    protected String           prefSigAlgs;

    @Option(name = "-httpget",
            required = false, description = "use HTTP GET for small request")
    protected Boolean          useHttpGetForSmallRequest;

    private OCSPRequestor      requestor;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads == null)
        {
            numThreads = 5;
        }

        if(hashAlgo == null)
        {
            hashAlgo = "SHA256";
        }

        ASN1ObjectIdentifier hashAlgoOid;

        hashAlgo = hashAlgo.trim().toUpperCase();

        if("SHA1".equalsIgnoreCase(hashAlgo) || "SHA-1".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if("SHA256".equalsIgnoreCase(hashAlgo) || "SHA-256".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha256;
        }
        else if("SHA384".equalsIgnoreCase(hashAlgo) || "SHA-384".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha384;
        }
        else if("SHA512".equalsIgnoreCase(hashAlgo) || "SHA-512".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha512;
        }
        else
        {
            throw new Exception("Unsupported hash algorithm " + hashAlgo);
        }

        List<Long> serialNumbers = new LinkedList<>();

        try
        {
            StringTokenizer tokens = new StringTokenizer(this.serialNumbers, ",");
            while(tokens.hasMoreTokens())
            {
                String token = tokens.nextToken().trim();
                StringTokenizer subtokens = new StringTokenizer(token, "- ");
                int countTokens = subtokens.countTokens();
                if(countTokens == 1)
                {
                    serialNumbers.add(Long.parseLong(subtokens.nextToken().trim()));
                }
                else if(countTokens == 2)
                {
                    int startSerial = Integer.parseInt(subtokens.nextToken().trim());
                    int endSerial = Integer.parseInt(subtokens.nextToken().trim());
                    if(startSerial < 1 || endSerial < 1 || startSerial > endSerial)
                    {
                        System.err.println("invalid serial number " + this.serialNumbers);
                        return null;
                    }
                    for(long i = startSerial; i <= endSerial; i++)
                    {
                        serialNumbers.add(i);
                    }
                }
                else
                {
                    System.err.println("invalid serial number " + this.serialNumbers);
                    return null;
                }
            }
        }catch(Exception e)
        {
            System.err.println("invalid serial numbers " + this.serialNumbers);
            return null;
        }

        if(numThreads < 1)
        {
            System.err.println("Invalid number of threads " + numThreads);
            return null;
        }

        URL serverUrl = new URL(serverURL == null ? DFLT_URL : serverURL);

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:        " + numThreads).append("\n");
        startMsg.append("Duration:       " + durationInSecond + " s").append("\n");
        startMsg.append("Serial numbers: " + this.serialNumbers).append("\n");
        startMsg.append("CA cert:        " + caCertFile).append("\n");
        startMsg.append("Server URL:     " + serverUrl.toString()).append("\n");
        startMsg.append("Hash:           " + hashAlgo).append("\n");
        System.out.print(startMsg.toString());

        X509Certificate caCert = IoCertUtil.parseCert(caCertFile);

        ClientRequestOptions options = new ClientRequestOptions();
        options.setUseNonce(useNonce == null ? false : useNonce.booleanValue());
        options.setHashAlgorithmId(hashAlgoOid);

        if(useHttpGetForSmallRequest != null)
        {
            options.setUseHttpGetForRequest(useHttpGetForSmallRequest.booleanValue());
        }

        if(prefSigAlgs != null)
        {
            StringTokenizer st = new StringTokenizer(prefSigAlgs, ",;: \t");
            List<String> sortedList = new ArrayList<>(st.countTokens());
            while(st.hasMoreTokens())
            {
                sortedList.add(st.nextToken());
            }

            options.setPreferredSignatureAlgorithms2(sortedList);
        }

        OcspLoadTest loadTest = new OcspLoadTest(requestor, serialNumbers,
                caCert, serverUrl, options);
        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }

    public OCSPRequestor getRequestor()
    {
        return requestor;
    }

    public void setRequestor(OCSPRequestor requestor)
    {
        this.requestor = requestor;
    }
}
