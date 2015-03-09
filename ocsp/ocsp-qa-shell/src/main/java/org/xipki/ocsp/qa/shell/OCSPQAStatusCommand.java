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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.xipki.common.SecurityUtil;
import org.xipki.ocsp.client.api.OCSPRequestor;
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
    @Option(name = "-expError",
            description = "Expected error. Valid values are , " + OCSPError.errorText)
    private String expectedErrorText;

    @Option(name = "-expStatus",
            multiValued = true,
            description = "Expected status. Valid values are \n" + CertStatus.certStatusesText + ",\nmulti values allowed")
    private List<String> expectedStatusTexts;

    @Option(name = "-expSigalg",
            description = "Expected signature algorithm")
    private String expectedSigalgo;

    @Option(name = "-expNextupdate",
            description = "Occurence of nextUpdate. Valid values are " + Occurrence.occurencesText)
    private String nextUpdateOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expCerthash",
            description = "Occurence of certHash. Valid values are " + Occurrence.occurencesText)
    private String certhashOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expNonce",
            description = "Occurence of nonce. Valid values are " + Occurrence.occurencesText)
    private String nonceOccurrenceText = Occurrence.optional.name();

    @Override
    protected void checkParameters(X509Certificate respIssuer,
            List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
        if(isBlank(expectedErrorText) && isEmpty(expectedStatusTexts))
        {
            throw new Exception("Neither expError nor expStatus is set, this is not permitted");
        }

        if(isNotBlank(expectedErrorText) && isNotEmpty(expectedStatusTexts))
        {
            throw new Exception("Both expError and expStatus are set, this is not permitted");
        }

        if(isNotEmpty(expectedStatusTexts))
        {
            if(expectedStatusTexts.size() != serialNumbers.size())
            {
                throw new Exception("Number of expStatus is invalid: " + (expectedStatusTexts.size()) +
                        ", it should be " + serialNumbers.size());
            }
        }
    }

    @Override
    protected Object processResponse(OCSPResp response,
            X509Certificate respIssuer, List<BigInteger> serialNumbers,
            Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
        OCSPError expectedOcspError = null;
        if(isNotBlank(expectedErrorText))
        {
            expectedOcspError = OCSPError.getOCSPError(expectedErrorText);
        }

        Map<BigInteger, CertStatus> expectedStatuses = null;
        if(isNotEmpty(expectedStatusTexts))
        {
            expectedStatuses = new HashMap<>();
            final int n = serialNumbers.size();

            for(int i = 0; i < n; i++)
            {
                String expectedStatusText = expectedStatusTexts.get(i);
                expectedStatuses.put(serialNumbers.get(i),
                        CertStatus.getCertStatus(expectedStatusText));
            }
        }

        Occurrence nextupdateOccurrence = Occurrence.getOccurrence(nextUpdateOccurrenceText);
        Occurrence certhashOccurrence = Occurrence.getOccurrence(certhashOccurrenceText);
        Occurrence nonceOccurrence = Occurrence.getOccurrence(nonceOccurrenceText);

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

            if(expectedOcspError.getStatus() == e.getStatus())
            {
                return null;
            }
            else
            {
                throw new ViolationException("OCSP error expected='" + expectedOcspError.name() +
                        "', is='" + OCSPError.getOCSPError(e.getStatus()).name() + "'");
            }
        }

        if(expectedOcspError != null)
        {
            throw new ViolationException("OCSP error expected='" + expectedOcspError.name() +
                    "', is='successful'");
        }

        // check the signature if available
        if(null == basicResp.getSignature())
        {
            throw new ViolationException("Response is not signed");
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

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            throw new ViolationException("Received no status from server");
        }
        else if(n != serialNumbers.size())
        {
            throw new ViolationException("Received status with " + n +
                    " single responses from server, but " + serialNumbers.size() + " was requested");
        }

        X509CertificateHolder[] responderCerts = basicResp.getCerts();
        if(responderCerts == null || responderCerts.length < 1)
        {
            throw new ViolationException("No responder certificate is contained in the response");
        }

        X509CertificateHolder respSigner = responderCerts[0];

        for(int i = 0; i < n; i++)
        {
            SingleResp singleResp = singleResponses[i];
            if(respSigner.isValidOn(singleResp.getThisUpdate()) == false)
            {
                throw new ViolationException("Responder certificate is not valid on the thisUpdate[ " + i + "]" +
                        singleResp.getThisUpdate());
            }
        }

        PublicKey responderPubKey = KeyUtil.generatePublicKey(responderCerts[0].getSubjectPublicKeyInfo());
        ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
        boolean sigValid = basicResp.isSignatureValid(cvp);
        if(sigValid == false)
        {
            throw new ViolationException("Response is equipped with invalid signature");
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
                throw new ViolationException("Responder signer is not trusted");
            }
        }

        Extension nonceExtn = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        checkOccurrence("nonce", nonceExtn, nonceOccurrence);

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        for(int i = 0; i < n; i++)
        {
            SingleResp singleResp = singleResponses[i];
            BigInteger serialNumber = singleResp.getCertID().getSerialNumber();
            CertStatus expectedStatus = expectedStatuses.get(serialNumber);

            byte[] encodedCert = null;
            if(encodedCerts != null)
            {
                encodedCert = encodedCerts.get(serialNumber);
            }

            try
            {
                checkSingleCert(singleResp, expectedStatus, encodedCert,
                        extendedRevoke, nextupdateOccurrence, certhashOccurrence);
            }catch(Exception e)
            {
                throw new ViolationException("SingleResponse[" + i + "]: " + e.getMessage());
            }
        }

        return null;
    }

    private void checkSingleCert(SingleResp singleResp,
            CertStatus expectedStatus, byte[] encodedCert,
            boolean extendedRevoke, Occurrence nextupdateOccurrence,
            Occurrence certhashOccurrence)
    throws Exception
    {
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
                        throw new ViolationException("REMOVE_FROM_CRL as reason in OCSP response is invalid");
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
            throw new ViolationException("Unknown certstatus: " + singleCertStatus.getClass().getName());
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
