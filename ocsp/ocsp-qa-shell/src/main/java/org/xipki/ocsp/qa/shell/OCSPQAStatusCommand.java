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

package org.xipki.ocsp.qa.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1Encodable;
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
import org.xipki.common.CRLReason;
import org.xipki.common.IoUtil;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.SecurityUtil;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.shell.BaseOCSPStatusCommand;
import org.xipki.ocsp.client.shell.OCSPResponseUnsuccessfulException;
import org.xipki.ocsp.client.shell.OCSPUtils;
import org.xipki.security.KeyUtil;
import org.xipki.security.SignerUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-qa", name = "ocsp-status", description="Request certificate status (QA)")
public class OCSPQAStatusCommand extends BaseOCSPStatusCommand
{
    @Option(name = "-serial",
            description = "Serial number")
    protected String serialNumber;

    @Option(name = "-cert",
            description = "Certificate")
    protected String certFile;

    @Option(name = "-expError",
            description = "Expected error. Valid values are , " + OCSPError.errorText)
    protected String expectedErrorText;

    @Option(name = "-expStatus",
            description = "Expected status. Valid values are " + CertStatus.certStatusesText)
    protected String expectedStatusText;

    @Option(name = "-expSigalg",
            description = "Expected signature algorithm")
    protected String expectedSigalgo;

    @Option(name = "-expNextupdate",
            description = "Occurence of nextUpdate. Valid values are " + Occurrence.occurencesText)
    protected String nextUpdateOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expCerthash",
            description = "Occurence of certHash. Valid values are " + Occurrence.occurencesText)
    protected String certhashOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expNonce",
            description = "Occurence of nonce. Valid values are " + Occurrence.occurencesText)
    protected String nonceOccurrenceText = Occurrence.optional.name();

    @Override
    protected Object _doExecute()
    throws Exception
    {
        if(isBlank(serialNumber) && isBlank(certFile))
        {
            throw new Exception("Neither serialNumber nor certFile is set, this is not permitted");
        }

        if(isNotBlank(serialNumber) && isNotBlank(certFile))
        {
            throw new Exception("Both serialNumber and certFile are set, this is not permitted");
        }

        if(isBlank(expectedErrorText) && isBlank(expectedStatusText))
        {
            throw new Exception("Neither expError nor expStatus is set, this is not permitted");
        }

        if(isNotBlank(expectedErrorText) && isNotBlank(expectedStatusText))
        {
            throw new Exception("Both expError and expStatus are set, this is not permitted");
        }

        OCSPError expectedOcspError = null;
        if(isNotBlank(expectedErrorText))
        {
            expectedOcspError = OCSPError.getOCSPError(expectedErrorText);
        }

        CertStatus expectedStatus = null;
        if(isNotBlank(expectedStatusText))
        {
            expectedStatus = CertStatus.getCertStatus(expectedStatusText);
        }

        Occurrence nextupdateOccurrence = Occurrence.getOccurrence(nextUpdateOccurrenceText);
        Occurrence certhashOccurrence = Occurrence.getOccurrence(certhashOccurrenceText);
        Occurrence nonceOccurrence = Occurrence.getOccurrence(nonceOccurrenceText);

        X509Certificate issuerCert = SecurityUtil.parseCert(issuerCertFile);

        byte[] encodedCert = null;
        BigInteger sn;
        if(certFile != null)
        {
            encodedCert = IoUtil.read(certFile);
            X509Certificate cert = SecurityUtil.parseCert(certFile);

            if(SecurityUtil.issues(issuerCert, cert) == false)
            {
                err("certificate " + certFile + " is not issued by the given CA");
                return null;
            }

            sn = cert.getSerialNumber();

            if(isBlank(serverURL))
            {
                List<String> ocspUrls = SecurityUtil.extractOCSPUrls(cert);
                if(ocspUrls.size() > 0)
                {
                    serverURL = ocspUrls.get(0);
                }
            }
        }
        else
        {
            sn = new BigInteger(serialNumber);
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

        OCSPResp response = null;
        try
        {
            response = requestor.ask(issuerCert, sn, serverUrl, options, debug);
        } finally
        {
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
        }

        BasicOCSPResp basicResp = null;
        try
        {
            basicResp = OCSPUtils.extractBasicOCSPResp(response);
        }catch(OCSPResponseUnsuccessfulException e)
        {
            if(expectedOcspError == null)
            {
                throw e;
            }

            if(expectedOcspError.getCode() == e.getStatus())
            {
                return null;
            }
            else
            {
                throw new ViolationException("OCSP error expected='" + expectedOcspError.getCode() +
                        "', is='" + e.getStatus() + "'");
            }
        }

        if(expectedOcspError != null)
        {
            throw new ViolationException("OCSP error expected='" + expectedOcspError.getCode() +
                    "', is='0'");
        }

        // check the signature if available
        if(null == basicResp.getSignature())
        {
            throw new Exception("Response is not signed");
        }

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            throw new Exception("Received no status from server");
        }
        else if(n != 1)
        {
            throw new Exception("Received status with " + n +
                    " single responses from server, but 1 was requested");
        }

        SingleResp singleResp = singleResponses[0];
        X509CertificateHolder[] responderCerts = basicResp.getCerts();
        if(responderCerts == null || responderCerts.length < 1)
        {
            throw new Exception("No responder certificate is contained in the response");
        }

        X509CertificateHolder respSigner = responderCerts[0];

        if(respSigner.isValidOn(singleResp.getThisUpdate()) == false)
        {
            throw new Exception("Responder certificate is not valid on " + singleResp.getThisUpdate());
        }

        PublicKey responderPubKey = KeyUtil.generatePublicKey(responderCerts[0].getSubjectPublicKeyInfo());
        ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
        boolean sigValid = basicResp.isSignatureValid(cvp);
        if(sigValid == false)
        {
            throw new Exception("Response is equipped with invalid signature");
        }

        if(respIssuer != null)
        {
            X509Certificate jceRespSigner = new X509CertificateObject(respSigner.toASN1Structure());
            if(SecurityUtil.issues(respIssuer, jceRespSigner))
            {
                jceRespSigner.verify(respIssuer.getPublicKey());
            }
            else
            {
                throw new Exception("Responder signer is not trusted");
            }
        }

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;
        Extension nonceExtn = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        checkOccurrence("nonce", nonceExtn, nonceOccurrence);

        CertificateStatus singleCertStatus = singleResp.getCertStatus();

        CertStatus status ;
        if(singleCertStatus == null)
        {
            status = CertStatus.good;
        }
        else if(singleCertStatus instanceof RevokedStatus)
        {
            RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
            Date revTime = revStatus.getRevocationTime();

            if(revStatus.hasRevocationReason())
            {
                int reason = revStatus.getRevocationReason();
                if(extendedRevoke &&
                        reason == CRLReason.CERTIFICATE_HOLD.getCode() &&
                        revTime.getTime() == 0)
                {
                    status = CertStatus.unknown;
                }
                else
                {
                    CRLReason revocationReason = CRLReason.forReasonCode(reason);
                    switch(revocationReason)
                    {
                    case UNSPECIFIED:
                        status = CertStatus.unspecified;
                        break;
                    case KEY_COMPROMISE:
                        status = CertStatus.keyCompromise;
                        break;
                    case CA_COMPROMISE:
                        status = CertStatus.cACompromise;
                        break;
                    case AFFILIATION_CHANGED:
                        status = CertStatus.affiliationChanged;
                        break;
                    case SUPERSEDED:
                        status = CertStatus.superseded;
                        break;
                    case CERTIFICATE_HOLD:
                        status = CertStatus.certificateHold;
                        break;
                    case REMOVE_FROM_CRL:
                        throw new Exception("REMOVE_FROM_CRL as reason in OCSP response is invalid");
                    case PRIVILEGE_WITHDRAWN:
                        status = CertStatus.privilegeWithdrawn;
                        break;
                    case AA_COMPROMISE:
                        status = CertStatus.aACompromise;
                        break;
                    default:
                        throw new RuntimeException("should not reach here, unknwon CRLReason " + revocationReason);
                    }
                }
            }
            else
            {
                status = CertStatus.rev_noreason;
            }
        }
        else if(singleCertStatus instanceof UnknownStatus)
        {
            status = CertStatus.issuerUnknown;
        }
        else
        {
            throw new Exception("Unknown certstatus: " + singleCertStatus.getClass().getName());
        }

        if(expectedStatus != status)
        {
            throw new ViolationException("status expected='" + expectedStatus +
                    "', is='" + status + "'");
        }

        Date nextUpdate = singleResp.getNextUpdate();
        checkOccurrence("nextUpdate", nextUpdate, nextupdateOccurrence);

        Extension extension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
        checkOccurrence("certHash", extension, certhashOccurrence);
        if(extension != null)
        {
            ASN1Encodable extensionValue = extension.getParsedValue();
            CertHash certHash = CertHash.getInstance(extensionValue);
            ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
            byte[] hashValue = certHash.getCertificateHash();

            if(encodedCert != null)
            {
                MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
                byte[] expectedHashValue = md.digest(encodedCert);
                if(Arrays.equals(expectedHashValue, hashValue) == false)
                {
                    throw new ViolationException("certHash does not match the requested certificate");
                }
            }
        }

        if(expectedSigalgo != null)
        {
            ASN1ObjectIdentifier sigAlgOid = basicResp.getSignatureAlgOID();

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

            if(sigAlgName.equalsIgnoreCase(expectedSigalgo) == false)
            {
                throw new ViolationException("expected signature algorithm is '" + expectedSigalgo +
                        "', but is '" + sigAlgName + "");
            }
        }

        return null;
    }

    private static void checkOccurrence(String targetName, Object target, Occurrence occurrence)
    throws ViolationException
    {
        switch (occurrence)
        {
        case optional:
            return;
        case forbidden:
            if(target != null)
            {
                throw new ViolationException(targetName + " is present, but none is expected");
            }
            break;
        case required:
            if(target == null)
            {
                throw new ViolationException(targetName + " is absent, but it is expected");
            }
            break;
        default:
            break;
        }
    }

}
