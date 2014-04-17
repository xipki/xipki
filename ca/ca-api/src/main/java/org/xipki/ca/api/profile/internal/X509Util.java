/*
 * Copyright 2014 xipki.org
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

package org.xipki.ca.api.profile.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.CertificatePolicyInformation;
import org.xipki.ca.api.profile.CertificatePolicyQualifier;
import org.xipki.ca.api.profile.KeyUsage;

public class X509Util
{

    public static BasicConstraints createBasicConstraints(boolean isCa, Integer pathLen)
    {
        BasicConstraints basicConstraints;
        if(isCa)
        {
            if(pathLen != null)
            {
                basicConstraints = new BasicConstraints(pathLen);
            }
            else
            {
                basicConstraints = new BasicConstraints(true);
            }
        }
        else
        {
            basicConstraints = new BasicConstraints(false);
        }
        return basicConstraints;
    }

    public static org.bouncycastle.asn1.x509.KeyUsage createKeyUsage(Set<KeyUsage> keyUsages)
    {
        if(keyUsages == null || keyUsages.isEmpty())
        {
            return null;
        }

        int usage = 0;
        for (KeyUsage keyUsage : keyUsages)
        {
            switch (keyUsage)
            {
                case contentCommitment:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
                    break;
                case cRLSign:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
                    break;
                case dataEncipherment:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
                    break;
                case decipherOnly:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.decipherOnly;
                    break;
                case digitalSignature:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
                    break;
                case encipherOnly:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.encipherOnly;
                    break;
                case keyAgreement:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
                    break;
                case keyCertSign:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
                    break;
                case keyEncipherment:
                    usage |= org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
                    break;
                default:
                    break;
            }
        }

        return new org.bouncycastle.asn1.x509.KeyUsage(usage);
    }

    public static ExtendedKeyUsage createExtendedUsage(Set<ASN1ObjectIdentifier> keyUsages)
    {
        if(keyUsages == null || keyUsages.isEmpty())
        {
            return null;
        }

        KeyPurposeId[] kps = new KeyPurposeId[keyUsages.size()];

        int i = 0;
        for (ASN1ObjectIdentifier oid : keyUsages)
        {
            kps[i++] = KeyPurposeId.getInstance(oid);
        }

        return new ExtendedKeyUsage(kps);
    }

    public static AuthorityInformationAccess createAuthorityInformationAccess(List<String> ocspUris)
    {
        if(ocspUris != null && ocspUris.isEmpty())
        {
            return null;
        }

        List<AccessDescription> accessDescriptions = new ArrayList<AccessDescription>(ocspUris.size());
        for(String uri : ocspUris)
        {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
            accessDescriptions.add(new AccessDescription(X509ObjectIdentifiers.id_ad_ocsp, gn));
        }

        DERSequence seq = new DERSequence(accessDescriptions.toArray(new AccessDescription[0]));
        return AuthorityInformationAccess.getInstance(seq);
    }

    public static CRLDistPoint createCRLDistributionPoints(List<String> crlUris,
            X500Principal caSubject, X500Principal crlSignerSubject)
    throws IOException, CertProfileException
    {
        if(crlUris == null || crlUris.isEmpty())
        {
            return null;
        }

        int n = crlUris.size();
        DistributionPoint[] points = new DistributionPoint[n];

        for(int i = 0; i < n; i++)
        {
            // Distribution Point
            GeneralNames gns = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUris.get(i)));
            DistributionPointName pointName = new DistributionPointName(gns);

            GeneralNames crlIssuer = null;
            if(crlSignerSubject != null && !crlSignerSubject.equals(caSubject))
            {
                X500Name bcCrlSignerSubject = X500Name.getInstance(crlSignerSubject.getEncoded());
                GeneralName crlIssuerName = new GeneralName(bcCrlSignerSubject);
                crlIssuer = new GeneralNames(crlIssuerName);
            }

            points[i++] = new DistributionPoint(pointName, null, crlIssuer);
        }

        return new CRLDistPoint(points);
    }

    public static CertificatePolicies createCertificatePolicies(List<CertificatePolicyInformation> policyInfos)
            throws CertProfileException
    {
        if(policyInfos == null || policyInfos.isEmpty())
        {
            return null;
        }

        int n = policyInfos.size();
        PolicyInformation[] pInfos = new PolicyInformation[n];

        int i = 0;
        for(CertificatePolicyInformation policyInfo : policyInfos)
        {
            String policyId = policyInfo.getCertPolicyId();
            List<CertificatePolicyQualifier> qualifiers = policyInfo.getQualifiers();

            ASN1Sequence policyQualifiers = null;
            if(qualifiers != null)
            {
                List<PolicyQualifierInfo> qualifierInfos = new ArrayList<PolicyQualifierInfo>(qualifiers.size());
                for(CertificatePolicyQualifier qualifier : qualifiers)
                {
                    PolicyQualifierInfo qualifierInfo ;
                    if(qualifier.getCpsUri() != null)
                    {
                        qualifierInfo = new PolicyQualifierInfo(qualifier.getCpsUri());
                    }
                    else if(qualifier.getUserNotice() != null)
                    {
                        UserNotice userNotice = new UserNotice(null, qualifier.getUserNotice());
                        qualifierInfo = new PolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_unotice,
                                userNotice);
                    }
                    else
                    {
                        qualifierInfo = null;
                    }

                    if(qualifierInfo != null)
                    {
                        qualifierInfos.add(qualifierInfo);
                    }
                    //PolicyQualifierId qualifierId
                }

                policyQualifiers = new DERSequence(qualifierInfos.toArray(new PolicyQualifierInfo[0]));

            }

            ASN1ObjectIdentifier policyOid = new ASN1ObjectIdentifier(policyId);
            if(policyQualifiers == null)
            {
                pInfos[i] = new PolicyInformation(policyOid);
            }
            else
            {
                pInfos[i] = new PolicyInformation(policyOid, policyQualifiers);
            }
            i++;
        }

        return new CertificatePolicies(pInfos);
    }


}
