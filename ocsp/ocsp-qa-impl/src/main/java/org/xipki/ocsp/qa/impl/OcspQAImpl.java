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

package org.xipki.ocsp.qa.impl;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
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
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.CRLReason;
import org.xipki.common.qa.ValidationIssue;
import org.xipki.common.qa.ValidationResult;
import org.xipki.common.util.SecurityUtil;
import org.xipki.ocsp.qa.api.Occurrence;
import org.xipki.ocsp.qa.api.OcspCertStatus;
import org.xipki.ocsp.qa.api.OcspError;
import org.xipki.ocsp.qa.api.OcspQA;
import org.xipki.ocsp.qa.api.OcspResponseOption;
import org.xipki.security.KeyUtil;
import org.xipki.security.SignerUtil;

/**
 * @author Lijun Liao
 */

public class OcspQAImpl implements OcspQA
{
    public static final ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs = OCSPObjectIdentifiers.id_pkix_ocsp.branch("8");
    public static final ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke = OCSPObjectIdentifiers.id_pkix_ocsp.branch("9");

    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(OcspQAImpl.class);

    public OcspQAImpl()
    {
    }

    public void init()
    {
    }

    public void shutdown()
    {
    }

    @Override
    public ValidationResult checkOCSP(
            OCSPResp response,
            X509Certificate issuer,
            List<BigInteger> serialNumbers,
            Map<BigInteger, byte[]> encodedCerts,
            OcspError expectedOcspError,
            Map<BigInteger, OcspCertStatus> expectedOcspStatuses,
            OcspResponseOption responseOption)
    {
        List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

        int status = response.getStatus();

        // Response status
        {
            ValidationIssue issue = new ValidationIssue("OCSP.STATUS", "Response.status");
            resultIssues.add(issue);
            if(expectedOcspError != null)
            {
                if(status != expectedOcspError.getStatus())
                {
                    issue.setFailureMessage("is '" + status +"', but expected '" + expectedOcspError.getStatus() + "'");
                }
            }
            else
            {
                if(status != 0)
                {
                    issue.setFailureMessage("is '" + status +"', but expected '0'");
                }
            }
        }

        if(status != 0)
        {
            return new ValidationResult(resultIssues);
        }

        ValidationIssue encodingIssue = new ValidationIssue("OCSP.ENCODING", "response encoding");
        resultIssues.add(encodingIssue);

        BasicOCSPResp basicResp;
        {
            try
            {
                basicResp = (BasicOCSPResp) response.getResponseObject();
            } catch (OCSPException e)
            {
                encodingIssue.setFailureMessage(e.getMessage());
                return new ValidationResult(resultIssues);
            }
        }

        SingleResp[] singleResponses = basicResp.getResponses();

        {
            ValidationIssue issue = new ValidationIssue("OCSP.RESPONSES.NUM", "number of single responses");
            resultIssues.add(issue);

            int n = singleResponses == null ? 0 : singleResponses.length;
            if(n == 0)
            {
                issue.setFailureMessage("Received no status from server");
            }
            else if(n != serialNumbers.size())
            {
                issue.setFailureMessage("is '" + n +"', but expected '" + serialNumbers.size() +  "'");
            }

            if(issue.isFailed())
            {
                return new ValidationResult(resultIssues);
            }
        }

        {
            boolean hasSignature =basicResp.getSignature() != null;

            {
                // check the signature if available
                ValidationIssue issue = new ValidationIssue("OCSP.SIG", "signature presence");
                resultIssues.add(issue);
                if(hasSignature == false)
                {
                    issue.setFailureMessage("Response is not signed");
                }
            }

            if(hasSignature)
            {
                {
                    // signature algorithm
                    ValidationIssue issue = new ValidationIssue("OCSP.SIG.ALG", "signature algorithm");
                    resultIssues.add(issue);

                    String expectedSigalgo = responseOption.getSignatureAlgName();
                    if(expectedSigalgo != null)
                    {
                        AlgorithmIdentifier sigAlg = basicResp.getSignatureAlgorithmID();
                        String sigAlgName = SignerUtil.getSignatureAlgoName(sigAlg);
                        if(sigAlgName.equalsIgnoreCase(expectedSigalgo) == false)
                        {
                            issue.setFailureMessage("is '" + sigAlgName +"', but expected '" + expectedSigalgo + "'");
                        }
                    }
                }

                // signer certificate
                ValidationIssue sigSignerCertIssue = new ValidationIssue("OCSP.SIGNERCERT", "signer certificate");
                resultIssues.add(sigSignerCertIssue);

                // signature validation
                ValidationIssue sigValIssue = new ValidationIssue("OCSP.SIG.VALIDATION", "signature validation");
                resultIssues.add(sigValIssue);

                X509CertificateHolder[] responderCerts = basicResp.getCerts();
                if(responderCerts == null || responderCerts.length < 1)
                {
                    sigSignerCertIssue.setFailureMessage("No responder certificate is contained in the response");
                    sigValIssue.setFailureMessage("Could not find certificate to validate signature");
                }
                else
                {
                    X509CertificateHolder respSigner = responderCerts[0];

                    ValidationIssue issue = new ValidationIssue("OCSP.SIGNERCERT.TRUST", "signer certificate validation");
                    resultIssues.add(issue);

                    for(int i = 0; i < singleResponses.length; i++)
                    {
                        SingleResp singleResp = singleResponses[i];
                        if(respSigner.isValidOn(singleResp.getThisUpdate()) == false)
                        {
                            issue.setFailureMessage("Responder certificate is not valid on the thisUpdate[ " + i + "]" +
                                    singleResp.getThisUpdate());
                        }
                    }

                    if(issue.isFailed() == false)
                    {
                        X509Certificate respIssuer = responseOption.getRespIssuer();
                        if(respIssuer != null)
                        {
                            X509Certificate jceRespSigner;
                            try
                            {
                                jceRespSigner = new X509CertificateObject(respSigner.toASN1Structure());
                                if(SecurityUtil.issues(respIssuer, jceRespSigner))
                                {
                                    jceRespSigner.verify(respIssuer.getPublicKey());
                                }
                                else
                                {
                                    issue.setFailureMessage("Responder signer is not trusted");
                                }
                            }catch(Exception e)
                            {
                                issue.setFailureMessage("Responder signer is not trusted");
                            }
                        }
                    }

                    try
                    {
                        PublicKey responderPubKey = KeyUtil.generatePublicKey(respSigner.getSubjectPublicKeyInfo());
                        ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
                        boolean sigValid = basicResp.isSignatureValid(cvp);
                        if(sigValid == false)
                        {
                            sigValIssue.setFailureMessage("signature is invalid");
                        }
                    }catch(Exception e)
                    {
                        sigValIssue.setFailureMessage("error while validating signature");
                    }
                }
            }
        }

        {
            // nonce
            Extension nonceExtn = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            resultIssues.add(checkOccurrence("OCSP.NONCE", nonceExtn, responseOption.getNonceOccurrence()));
        }

        boolean extendedRevoke = basicResp.getExtension(id_pkix_ocsp_extendedRevoke) != null;

        for(int i = 0; i < singleResponses.length; i++)
        {
            SingleResp singleResp = singleResponses[i];
            BigInteger serialNumber = singleResp.getCertID().getSerialNumber();
            OcspCertStatus expectedStatus = expectedOcspStatuses.get(serialNumber);

            byte[] encodedCert = null;
            if(encodedCerts != null)
            {
                encodedCert = encodedCerts.get(serialNumber);
            }

            List<ValidationIssue> issues = checkSingleCert(
                    i, singleResp,
                    expectedStatus, encodedCert, extendedRevoke,
                    responseOption.getNextUpdateOccurrence(),
                    responseOption.getCerthashOccurrence(),
                    responseOption.getCerthashAlgId());
            resultIssues.addAll(issues);
        }

        return new ValidationResult(resultIssues);
    }

    private List<ValidationIssue> checkSingleCert(
            int index, SingleResp singleResp,
            OcspCertStatus expectedStatus, byte[] encodedCert,
            boolean extendedRevoke, Occurrence nextupdateOccurrence,
            Occurrence certhashOccurrence, ASN1ObjectIdentifier certhashAlg)
    {
        List<ValidationIssue> issues = new LinkedList<>();
        {
            // status
            ValidationIssue issue = new ValidationIssue("OCSP.RESPONSE." + index + ".STATUS", "certificate status");
            issues.add(issue);

            CertificateStatus singleCertStatus = singleResp.getCertStatus();

            OcspCertStatus status = null;
            if(singleCertStatus == null)
            {
                status = OcspCertStatus.good;
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
                        status = OcspCertStatus.unknown;
                    }
                    else
                    {
                        CRLReason revocationReason = CRLReason.forReasonCode(reason);
                        switch(revocationReason)
                        {
                        case UNSPECIFIED:
                            status = OcspCertStatus.unspecified;
                            break;
                        case KEY_COMPROMISE:
                            status = OcspCertStatus.keyCompromise;
                            break;
                        case CA_COMPROMISE:
                            status = OcspCertStatus.cACompromise;
                            break;
                        case AFFILIATION_CHANGED:
                            status = OcspCertStatus.affiliationChanged;
                            break;
                        case SUPERSEDED:
                            status = OcspCertStatus.superseded;
                            break;
                        case CERTIFICATE_HOLD:
                            status = OcspCertStatus.certificateHold;
                            break;
                        case REMOVE_FROM_CRL:
                            status = OcspCertStatus.removeFromCRL;
                            break;
                        case PRIVILEGE_WITHDRAWN:
                            status = OcspCertStatus.privilegeWithdrawn;
                            break;
                        case AA_COMPROMISE:
                            status = OcspCertStatus.aACompromise;
                            break;
                        default:
                            issue.setFailureMessage("should not reach here, unknwon CRLReason " + revocationReason);
                            break;
                        }
                    }
                }
                else
                {
                    status = OcspCertStatus.rev_noreason;
                }
            }
            else if(singleCertStatus instanceof UnknownStatus)
            {
                status = OcspCertStatus.issuerUnknown;
            }
            else
            {
                issue.setFailureMessage("Unknown certstatus: " + singleCertStatus.getClass().getName());
            }

            if(issue.isFailed() == false && expectedStatus != status)
            {
                issue.setFailureMessage("is='" + status + "', but expected='" + expectedStatus + "'");
            }
        }

        {
            // nextUpdate
            Date nextUpdate = singleResp.getNextUpdate();
            checkOccurrence("OCSP.RESPONSE." + index + ".NEXTUPDATE", nextUpdate, nextupdateOccurrence);
        }

        Extension extension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
        {
            checkOccurrence("OCSP.RESPONSE." + index + ".CERTHASh", extension, certhashOccurrence);
        }

        if(extension != null)
        {
            ASN1Encodable extensionValue = extension.getParsedValue();
            CertHash certHash = CertHash.getInstance(extensionValue);
            ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
            if(certhashAlg != null)
            {
                // certHash algorithm
                ValidationIssue issue = new ValidationIssue("OCSP.RESPONSE." + index + ".CERTHASH.ALG", "certhash algorithm");
                issues.add(issue);

                ASN1ObjectIdentifier is = certHash.getHashAlgorithm().getAlgorithm();
                if(certhashAlg.equals(is) == false)
                {
                    issue.setFailureMessage("is '" + is.getId() +"', but expected '" + certhashAlg.getId() + "'");
                }
            }

            byte[] hashValue = certHash.getCertificateHash();
            if(encodedCert != null)
            {
                ValidationIssue issue = new ValidationIssue(
                        "OCSP.RESPONSE." + index + ".CERTHASH.VALIDITY", "certhash validity");
                issues.add(issue);

                try
                {
                    MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
                    byte[] expectedHashValue = md.digest(encodedCert);
                    if(Arrays.equals(expectedHashValue, hashValue) == false)
                    {
                        issue.setFailureMessage("certHash does not match the requested certificate");
                    }
                } catch (NoSuchAlgorithmException e)
                {
                    issue.setFailureMessage("NoSuchAlgorithm " + hashAlgOid.getId());
                }
            }
        }

        return issues;
    }

    private static ValidationIssue checkOccurrence(String targetName, Object target, Occurrence occurrence)
    {
        ValidationIssue issue = new ValidationIssue("OCSP." + targetName, targetName);
        if(occurrence == Occurrence.forbidden)
        {
            if(target != null)
            {
                issue.setFailureMessage(" is present, but none is expected");
            }
        }
        else if(occurrence == Occurrence.required)
        {
            if(target == null)
            {
                issue.setFailureMessage(" is absent, but it is expected");
            }
        }
        return issue;
    }

}
