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

package org.xipki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.CRLReason;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.IoUtil;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.SecurityUtil;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.KeyUtil;
import org.xipki.security.SignerUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ocsp", name = "status", description="Request certificate status")
public class OCSPStatusCommand extends AbstractOCSPStatusCommand
{
    @Option(name = "-respIssuer",
            required = false, description = "Certificate file of the responder's issuer")
    protected String respIssuerFile;

    @Option(name = "-serial",
            multiValued = true,
            description = "Serial number")
    protected List<String> serialNumbers;

    @Option(name = "-cert",
            multiValued = true,
            description = "Certificate")
    protected List<String> certFiles;

    @Option(name = "-url",
            required = false, description = "OCSP responder URL")
    protected String serverURL;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    @Option(name = "-reqout",
            required = false, description = "write DER encoded OCSP request to fie")
    protected String reqout;

    @Option(name = "-respout",
            required = false, description = "write DER encoded OCSP response to fie")
    protected String respout;

    private static final Map<ASN1ObjectIdentifier, String> extensionOidNameMap = new HashMap<>();
    static
    {
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        extensionOidNameMap.put(OCSPRequestor.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

    @Override
    protected Object _doExecute()
    throws Exception
    {
        if(isEmpty(serialNumbers) && isEmpty(certFiles))
        {
            err("Neither serialNumbers nor certFiles is set");
            return null;
        }

        X509Certificate issuerCert = SecurityUtil.parseCert(issuerCertFile);

        Map<BigInteger, byte[]> encodedCerts = null;
        List<BigInteger> sns = new LinkedList<>();
        if(isNotEmpty(certFiles))
        {
            encodedCerts = new HashMap<>(certFiles.size());

            String ocspUrl = null;
            for(String certFile : certFiles)
            {
                byte[] encodedCert = IoUtil.read(certFile);
                X509Certificate cert = SecurityUtil.parseCert(certFile);

                if(SecurityUtil.issues(issuerCert, cert) == false)
                {
                    err("certificate " + certFile + " is not issued by the given issuer");
                    return null;
                }

                if(isBlank(serverURL))
                {
                    List<String> ocspUrls = SecurityUtil.extractOCSPUrls(cert);
                    if(ocspUrls.size() > 0)
                    {
                        String url = ocspUrls.get(0);
                        if(ocspUrl != null && ocspUrl.equals(url) == false)
                        {
                            err("given certificates have different OCSP responder URL in certificate");
                            return null;
                        } else
                        {
                            ocspUrl = url;
                        }
                    }
                }

                BigInteger sn = cert.getSerialNumber();
                sns.add(sn);
                encodedCerts.put(sn, encodedCert);
            }

            if(isBlank(serverURL))
            {
                serverURL = ocspUrl;
            }
        }
        else
        {
            for(String serialNumber : serialNumbers)
            {
                BigInteger sn = new BigInteger(serialNumber);
                sns.add(sn);
            }
        }

        if(isBlank(serverURL))
        {
            err("Could not get URL for the OCSP responder");
            return null;
        }

        X509Certificate respIssuer  = null;
        if(respIssuerFile != null)
        {
            respIssuer = SecurityUtil.parseCert(IoUtil.expandFilepath(respIssuerFile));
        }

        URL serverUrl = new URL(serverURL);

        RequestOptions options = getRequestOptions();

        boolean saveReq = isNotBlank(reqout);
        boolean saveResp = isNotBlank(respout);
        RequestResponseDebug debug = null;
        if(saveReq || saveResp)
        {
            debug = new RequestResponseDebug();
        }

        OCSPResp response = requestor.ask(issuerCert, sns.toArray(new BigInteger[0]), serverUrl,
                options, debug);
        if(debug != null && debug.size() > 0)
        {
            RequestResponsePair reqResp = debug.get(0);
            if(saveReq)
            {
                byte[] bytes = reqResp.getRequest();
                if(bytes != null)
                {
                    IoUtil.save(reqout, bytes);
                }
            }

            if(saveResp)
            {
                byte[] bytes = reqResp.getResponse();
                if(bytes != null)
                {
                    IoUtil.save(respout, bytes);
                }
            }
        }

        BasicOCSPResp basicResp = OCSPUtils.extractBasicOCSPResp(response);

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            err("Received no status from server");
            return null;
        }

        if(n != sns.size())
        {
            err("Received status with " + n +
                    " single responses from server, but " + sns.size() + " were requested");
            return null;
        }

        Date[] thisUpdates = new Date[n];
        for(int i = 0; i < n; i++)
        {
            thisUpdates[i] = singleResponses[i].getThisUpdate();
        }

        // check the signature if available
        if(null == basicResp.getSignature())
        {
            out("Response is not signed");
        }
        else
        {
            X509CertificateHolder[] responderCerts = basicResp.getCerts();
            if(responderCerts == null || responderCerts.length < 1)
            {
                err("No responder certificate is contained in the response");
            }
            else
            {
                X509CertificateHolder respSigner = responderCerts[0];
                boolean validOn = true;
                for(Date thisUpdate : thisUpdates)
                {
                    validOn = respSigner.isValidOn(thisUpdate);
                    if(validOn == false)
                    {
                        err("Responder certificate is not valid on " + thisUpdate);
                        break;
                    }
                }

                if(validOn)
                {
                    PublicKey responderPubKey = KeyUtil.generatePublicKey(respSigner.getSubjectPublicKeyInfo());
                    ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
                    boolean sigValid = basicResp.isSignatureValid(cvp);

                    if(sigValid == false)
                    {
                        err("Response is equipped with invalid signature");
                    }
                    else
                    {
                        // verify the OCSPResponse signer
                        if(respIssuer != null)
                        {
                            boolean certValid = true;
                            X509Certificate jceRespSigner = new X509CertificateObject(respSigner.toASN1Structure());
                            if(SecurityUtil.issues(respIssuer, jceRespSigner))
                            {
                                try
                                {
                                    jceRespSigner.verify(respIssuer.getPublicKey());
                                }catch(SignatureException e)
                                {
                                    certValid = false;
                                }
                            }

                            if(certValid == false)
                            {
                                err("Response is equipped with valid signature but the OCSP signer is not trusted");
                            }
                        }
                        else
                        {
                            out("Response is equipped with valid signature");
                        }
                    }
                }

                if(verbose.booleanValue())
                {
                    out("Responder is " + SecurityUtil.getRFC4519Name(responderCerts[0].getSubject()));
                }
            }
        }

        for(int i = 0; i < n; i++)
        {
            if(n > 1)
            {
                out("---------------------------- " + i + " ----------------------------");
            }
            SingleResp singleResp = singleResponses[i];
            BigInteger serialNumber = singleResp.getCertID().getSerialNumber();

            CertificateStatus singleCertStatus = singleResp.getCertStatus();

            String status ;
            if(singleCertStatus == null)
            {
                status = "Good";
            }
            else if(singleCertStatus instanceof RevokedStatus)
            {
                RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
                Date revTime = revStatus.getRevocationTime();
                Date invTime = null;
                Extension ext = singleResp.getExtension(Extension.invalidityDate);
                if(ext != null)
                {
                    invTime = ASN1GeneralizedTime.getInstance(ext.getParsedValue()).getDate();
                }

                if(revStatus.hasRevocationReason())
                {
                    int reason = revStatus.getRevocationReason();
                    if(extendedRevoke &&
                            reason == CRLReason.CERTIFICATE_HOLD.getCode() &&
                            revTime.getTime() == 0)
                    {
                        status = "Unknown (RFC6960)";
                    }
                    else
                    {
                        StringBuilder sb = new StringBuilder("Revoked, reason = ");
                        sb.append(CRLReason.forReasonCode(reason).getDescription());
                        sb.append(", revocationTime = ");
                        sb.append(revTime);
                        if(invTime !=null)
                        {
                            sb.append(", invalidityTime = ");
                            sb.append(invTime);
                        }
                        status = sb.toString();
                    }
                }
                else
                {
                    status = "Revoked, no reason, revocationTime = " + revTime;
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

            StringBuilder msg = new StringBuilder();
            msg.append("SerialNumber: ").append(serialNumber);
            msg.append("\nCertificate status: ").append(status);

            if(verbose.booleanValue())
            {
                msg.append("\nthisUpdate: " + singleResp.getThisUpdate());
                msg.append("\nnextUpdate: " + singleResp.getNextUpdate());

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

                    if(encodedCerts != null)
                    {
                        byte[] encodedCert = encodedCerts.get(serialNumber);
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
                    for(int j = 0; j < size; j++)
                    {
                        ASN1ObjectIdentifier extensionOID = (ASN1ObjectIdentifier) extensionOIDs.get(j);
                        String name = extensionOidNameMap.get(extensionOID);
                        msg.append(name == null ? extensionOID.getId() : name);
                        if(j != size - 1)
                        {
                            msg.append(", ");
                        }
                    }
                }
            }

            out(msg.toString());
        }
        out("");

        return null;
    }

}
