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

package org.xipki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPResponseNotSuccessfullException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ocsp", name = "status", description="Request certificate status")
public class OCSPStatusCommand extends OsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";
    @Option(name = "-url",
            description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

    @Option(name = "-ca",
            required = true, description = "Required. CA certificate file")
    protected String            cacertFile;

    @Option(name = "-sn", aliases = { "--serialNumber" },
            description = "Serial number")
    protected String            serialNumber;

    @Option(name = "-cert",
            description = "Certificate")
    protected String            certFile;

    @Option(name = "-nonce",
            description = "Use nonce")
    protected Boolean            useNonce;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

    private OCSPRequestor      requestor;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(serialNumber == null && certFile == null)
        {
            System.out.println("Neither serialNumber nor certFile is not set");
            return null;
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

        X509Certificate caCert = IoCertUtil.parseCert(cacertFile);

        byte[] encodedCert = null;
        BigInteger sn;
        if(certFile != null)
        {
            encodedCert = IoCertUtil.read(certFile);
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            sn = cert.getSerialNumber();
        }
        else
        {
            sn = new BigInteger(serialNumber);
        }

        URL serverUrl = new URL(serverURL == null ? DFLT_URL : serverURL);

        RequestOptions options = new RequestOptions();
        options.setUseNonce(useNonce == null ? false : useNonce.booleanValue());
        options.setHashAlgorithmId(hashAlgoOid);

        BasicOCSPResp basicResp;
        try
        {
            basicResp = requestor.ask(caCert, sn, serverUrl, options);
        }catch(OCSPResponseNotSuccessfullException e)
        {
            System.err.println(e.getMessage());
            return null;
        }

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            System.err.println("Received no status from server");
        }
        else if(n != 1)
        {
            System.err.println("Received status with " + n + " single responses from server, but 1 was requested");
        }
        else
        {
            SingleResp singleResp = singleResponses[0];
            CertificateStatus singleCertStatus = singleResp.getCertStatus();

            String status ;
            if(singleCertStatus == null)
            {
                status = "Good";
            }
            else if(singleCertStatus instanceof RevokedStatus)
            {
                int reason = ((RevokedStatus) singleCertStatus).getRevocationReason();
                Date revTime = ((RevokedStatus) singleCertStatus).getRevocationTime();
                status = "Revocated, reason = "+ reason + ", revocationTime = " + revTime;
            }
            else if(singleCertStatus instanceof UnknownStatus)
            {
                status = "Unknown";
            }
            else
            {
                status = "ERROR";
            }

            StringBuilder msg = new StringBuilder("Certificate status: ");
            msg.append(status);

            Extension certHashExtension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
            if(certHashExtension != null)
            {
                msg.append("\nCertHash is provided:\n");
                ASN1Encodable extensionValue = certHashExtension.getParsedValue();
                CertHash certHash = CertHash.getInstance(extensionValue);
                ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
                byte[] hashValue = certHash.getCertificateHash();

                msg.append("\tHash algo : ").append(hashAlgOid.getId()).append("\n");
                msg.append("\tHash value: ").append(Hex.toHexString(hashValue)).append("\n");
                if(encodedCert != null)
                {
                    MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
                    byte[] expectedHashValue = md.digest(encodedCert);
                    if(Arrays.equals(expectedHashValue, hashValue))
                    {
                        msg.append("\tThis matches the requested certificate");
                    }
                    else
                    {
                        msg.append("\tThis differs from the requested certificate");
                    }
                }
            }

            System.out.println(msg.toString());
        }

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
