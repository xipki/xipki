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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.commands.Command;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
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
import org.xipki.common.security.CRLReason;
import org.xipki.common.util.AlgorithmUtil;
import org.xipki.common.util.X509Util;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.security.KeyUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ocsp", name = "status", description="request certificate status")
public class OCSPStatusCommand extends BaseOCSPStatusCommand
{
    @Override
    protected void checkParameters(
            final X509Certificate respIssuer,
            final List<BigInteger> serialNumbers,
            final Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
    }

    @Override
    protected Object processResponse(
            final OCSPResp response,
            final X509Certificate respIssuer,
            final X509Certificate issuer,
            final List<BigInteger> serialNumbers,
            final Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
        BasicOCSPResp basicResp = OCSPUtils.extractBasicOCSPResp(response);

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            throw new CmdFailure("received no status from server");
        }

        if(n != serialNumbers.size())
        {
            throw new CmdFailure("received status with " + n +
                    " single responses from server, but " + serialNumbers.size() + " were requested");
        }

        Date[] thisUpdates = new Date[n];
        for(int i = 0; i < n; i++)
        {
            thisUpdates[i] = singleResponses[i].getThisUpdate();
        }

        // check the signature if available
        if(null == basicResp.getSignature())
        {
            out("response is not signed");
        }
        else
        {
            X509CertificateHolder[] responderCerts = basicResp.getCerts();
            if(responderCerts == null || responderCerts.length < 1)
            {
                throw new CmdFailure("no responder certificate is contained in the response");
            }

            X509CertificateHolder respSigner = responderCerts[0];
            boolean validOn = true;
            for(Date thisUpdate : thisUpdates)
            {
                validOn = respSigner.isValidOn(thisUpdate);
                if(validOn == false)
                {
                    throw new CmdFailure("responder certificate is not valid on " + thisUpdate);
                }
            }

            if(validOn)
            {
                PublicKey responderPubKey = KeyUtil.generatePublicKey(respSigner.getSubjectPublicKeyInfo());
                ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
                boolean sigValid = basicResp.isSignatureValid(cvp);

                if(sigValid == false)
                {
                    throw new CmdFailure("response is equipped with invalid signature");
                }

                // verify the OCSPResponse signer
                if(respIssuer != null)
                {
                    boolean certValid = true;
                    X509Certificate jceRespSigner = new X509CertificateObject(respSigner.toASN1Structure());
                    if(X509Util.issues(respIssuer, jceRespSigner))
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
                        throw new CmdFailure(
                                "response is equipped with valid signature but the OCSP signer is not trusted");
                    }
                }
                else
                {
                    out("response is equipped with valid signature");
                }
            }

            if(verbose.booleanValue())
            {
                out("responder is " + X509Util.getRFC4519Name(responderCerts[0].getSubject()));
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
                status = "good";
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
                        status = "unknown (RFC6960)";
                    }
                    else
                    {
                        StringBuilder sb = new StringBuilder("revoked, reason = ");
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
                    status = "revoked, no reason, revocationTime = " + revTime;
                }
            }
            else if(singleCertStatus instanceof UnknownStatus)
            {
                status = "unknown (RFC2560)";
            }
            else
            {
                status = "ERROR";
            }

            StringBuilder msg = new StringBuilder();
            msg.append("serialNumber: ").append(serialNumber);
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

                AlgorithmIdentifier sigAlg = basicResp.getSignatureAlgorithmID();
                if(sigAlg == null)
                {
                    msg.append(("\nresponse is not signed"));
                }
                else
                {
                    String sigAlgName = AlgorithmUtil.getSignatureAlgoName(sigAlg);
                    if(sigAlgName == null)
                    {
                        sigAlgName = "unknown";
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
