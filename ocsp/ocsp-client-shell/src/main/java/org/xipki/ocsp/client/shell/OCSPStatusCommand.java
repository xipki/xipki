/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
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
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.CRLReason;
import org.xipki.common.IoCertUtil;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.KeyUtil;
import org.xipki.security.SignerUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ocsp", name = "status", description="Request certificate status")
public class OCSPStatusCommand extends AbstractOCSPStatusCommand
{
    @Option(name = "-serial",
            description = "Serial number")
    protected String serialNumber;

    @Option(name = "-cert",
            description = "Certificate")
    protected String certFile;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    private static final Map<ASN1ObjectIdentifier, String> extensionOidNameMap = new HashMap<>();
    static
    {
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        extensionOidNameMap.put(OCSPRequestor.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(serialNumber == null && certFile == null)
        {
            err("Neither serialNumber nor certFile is set");
            return null;
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

        URL serverUrl = getServiceURL();

        RequestOptions options = getRequestOptions();

        BasicOCSPResp basicResp;
        try
        {
            OCSPResp response = requestor.ask(caCert, sn, serverUrl, options);
            basicResp = (BasicOCSPResp) response.getResponseObject();
        } catch (OCSPException e)
        {
            throw new OCSPRequestorException(e);
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
                PublicKey responderPubKey = KeyUtil.generatePublicKey(responderCerts[0].getSubjectPublicKeyInfo());
                ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
                boolean sigValid = basicResp.isSignatureValid(cvp);
                if(sigValid == false)
                {
                    err("Response is equipped with invalid signature");
                }
                else
                {
                    err("Response is equipped with valid signature");
                }

                if(verbose.booleanValue())
                {
                    out("Responder is " + IoCertUtil.canonicalizeName(responderCerts[0].getSubject()));
                }
            }
        }

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            err("Received no status from server");
        }
        else if(n != 1)
        {
            err("Received status with " + n +
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

            StringBuilder msg = new StringBuilder("Certificate status: ");
            msg.append(status);

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

            out(msg.toString());
        }
        out("");

        return null;
    }
}
