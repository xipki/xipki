/*
 * Copyright (c) 2014 Lijun Liao
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
import org.xipki.security.SignerUtil;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ocsp", name = "status", description="Request certificate status")
public class OCSPStatusCommand extends OsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";
    @Option(name = "-url",
            description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

    @Option(name = "-cacert",
            required = true, description = "Required. CA certificate file")
    protected String            caCertFile;

    @Option(name = "-serial",
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

    @Option(name = "-sigalgs",
            required = false, description = "comma-seperated preferred signature algorithms")
    protected String           prefSigAlgs;

    @Option(name = "-httpget",
            required = false, description = "use HTTP GET for small request")
    protected Boolean          useHttpGetForSmallRequest;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show status verbosely")
    protected Boolean          verbose;

    private static final Map<ASN1ObjectIdentifier, String> extensionOidNameMap = new HashMap<>();
    static
    {
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        extensionOidNameMap.put(OCSPRequestor.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

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

        X509Certificate caCert = IoCertUtil.parseCert(caCertFile);

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

        BasicOCSPResp basicResp;
        try
        {
            basicResp = requestor.ask(caCert, sn, serverUrl, options);
        }catch(OCSPResponseNotSuccessfullException e)
        {
            System.err.println(e.getMessage());
            return null;
        }

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            System.err.println("Received no status from server");
        }
        else if(n != 1)
        {
            System.err.println("Received status with " + n +
                    " single responses from server, but 1 was requested");
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
                if(extendedRevoke &&
                        reason == CRLReason.CERTIFICATE_HOLD.getCode() &&
                        revTime.getTime() == 0)
                {
                    status = "Unknown (RFC6960)";
                }
                else
                {
                    status = "Revoked, reason = "+ CRLReason.forReasonCode(reason).getDescription() +
                            ", revocationTime = " + revTime;
                }
            }
            else if(singleCertStatus instanceof UnknownStatus)
            {
                status = "Unknown (RFC2560)";
            }
            else
            {
                status = "ERROR";
            }

            StringBuilder msg = new StringBuilder("Certificate status: ");
            msg.append(status);

            Extension extension = singleResp.getExtension(
                    ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
            if(extension != null)
            {
                msg.append("\nCertHash is provided:\n");
                ASN1Encodable extensionValue = extension.getParsedValue();
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

            if(verbose != null && verbose.booleanValue())
            {
                extension = singleResp.getExtension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
                if(extension != null)
                {
                    ASN1Encodable extensionValue = extension.getParsedValue();
                    ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(extensionValue);
                    msg.append("\nArchive-CutOff: ");
                    msg.append(time.getTimeString());
                }

                ASN1ObjectIdentifier sigAlgOid = basicResp.getSignatureAlgOID();
                if(sigAlgOid == null)
                {
                    msg.append(("\nresponse is not signed"));
                }
                else
                {
                    String sigAlgName;
                    if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOid))
                    {
                        BasicOCSPResponse asn1BasicOCSPResp =
                                BasicOCSPResponse.getInstance(basicResp.getEncoded());
                        sigAlgName = SignerUtil.getSignatureAlgoName(
                                asn1BasicOCSPResp.getSignatureAlgorithm());
                    }
                    else
                    {
                        sigAlgName = SignerUtil.getSignatureAlgoName(new AlgorithmIdentifier(sigAlgOid));
                    }
                    if(sigAlgName == null)
                    {
                        sigAlgName = "UNKNOWN";
                    }
                    msg.append("\nresponse is signed with ").append(sigAlgName);
                }

                // extensions
                msg.append("\nExtensions: ");

                List<?> extensionOIDs = basicResp.getExtensionOIDs();
                if(extensionOIDs == null || extensionOIDs.size() == 0)
                {
                    msg.append("-");
                }
                else
                {
                    int size = extensionOIDs.size();
                    for(int i = 0; i < size; i++)
                    {
                        ASN1ObjectIdentifier extensionOID = (ASN1ObjectIdentifier) extensionOIDs.get(i);
                        String name = extensionOidNameMap.get(extensionOID);
                        msg.append(name == null ? extensionOID.getId() : name);
                        if(i != size - 1)
                        {
                            msg.append(", ");
                        }
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
