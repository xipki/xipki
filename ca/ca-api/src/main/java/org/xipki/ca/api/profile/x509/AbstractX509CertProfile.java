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

package org.xipki.ca.api.profile.x509;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.RDNOccurrence;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.SecurityUtil;
import org.xipki.common.StringUtil;

/**
 * @author Lijun Liao
 */

public abstract class AbstractX509CertProfile
extends X509CertProfile
{
    private static Set<String> countryCodes;

    static
    {
        String[] codes =
        {
            "AD", "AE", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB",
            "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW",
            "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
            "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET",
            "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN",
            "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL",
            "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
            "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA",
            "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU",
            "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
            "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE",
            "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
            "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM",
            "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
            "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"};
        countryCodes = new HashSet<>();
        for(String code : codes)
        {
            countryCodes.add(code);
        }

        // consider new added codes
        String s = System.getProperty("org.xipki.countrycodes.extra");
        if(s != null)
        {
            countryCodes.addAll(StringUtil.split(s, ",; \t"));
        }
    }

    protected abstract Set<KeyUsage> getKeyUsage();

    protected abstract boolean isCa();

    protected abstract Integer getPathLenBasicConstraint();

    protected abstract Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences();

    protected void checkSubjectContent(X500Name requestedSubject)
    throws BadCertTemplateException
    {
        String c = getSubjectFieldFirstValue(requestedSubject, ObjectIdentifiers.DN_C, 0);
        if(c != null)
        {
            if(isCountryCodeValid(c) == false)
            {
                throw new BadCertTemplateException("invalid country code '" +  c + "'");
            }
        }
    }

    protected AbstractX509CertProfile()
    {
    }

    public boolean backwardsSubject()
    {
        return false;
    }

    protected String[] sortRDNs(ASN1ObjectIdentifier type, String[] values)
    {
        return values;
    }

    public Set<RDNOccurrence> getSubjectDNSubset()
    {
        return null;
    }

    @Override
    public Date getNotBefore(Date notBefore)
    {
        Date now = new Date();
        if(notBefore != null && notBefore.after(now))
        {
            return notBefore;
        }
        else
        {
            return now;
        }
    }

    @Override
    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
        verifySubjectDNOccurence(requestedSubject);
        checkSubjectContent(requestedSubject);

        RDN[] requstedRDNs = requestedSubject.getRDNs();
        Set<RDNOccurrence> occurences = getSubjectDNSubset();
        List<RDN> rdns = new LinkedList<>();
        List<ASN1ObjectIdentifier> types = backwardsSubject() ?
                ObjectIdentifiers.getBackwardDNs() : ObjectIdentifiers.getForwardDNs();

        for(ASN1ObjectIdentifier type : types)
        {
            RDNOccurrence occurrence = null;
            if(occurences != null)
            {
                occurrence = getRDNOccurrence(occurences, type);
                if(occurrence == null || occurrence.getMaxOccurs() < 1)
                {
                    continue;
                }
            }

            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = thisRDNs == null ? 0 : thisRDNs.length;
            if(n == 0)
            {
                continue;
            }

            if(n == 1)
            {
                String value = SecurityUtil.rdnValueToString(thisRDNs[0].getFirst().getValue());
                rdns.add(createSubjectRDN(value, type));
            }
            else
            {
                String[] values = new String[n];
                for(int i = 0; i < n; i++)
                {
                    values[i] = SecurityUtil.rdnValueToString(thisRDNs[i].getFirst().getValue());
                }
                values = sortRDNs(type, values);

                for(String value : values)
                {
                    rdns.add(createSubjectRDN(value, type));
                }
            }
        }

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    protected static RDNOccurrence getRDNOccurrence(Set<RDNOccurrence> occurences, ASN1ObjectIdentifier type)
    {
        for(RDNOccurrence occurence : occurences)
        {
            if(occurence.getType().equals(type))
            {
                return occurence;
            }
        }
        return null;
    }

    protected static RDN[] getRDNs(RDN[] rdns, ASN1ObjectIdentifier type)
    {
        List<RDN> ret = new ArrayList<>(1);
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            if(rdn.getFirst().getType().equals(type))
            {
                ret.add(rdn);
            }
        }

        return ret.isEmpty() ? null : ret.toArray(new RDN[0]);
    }

    protected EnvironmentParameterResolver parameterResolver;
    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        this.parameterResolver = parameterResolver;
    }

    @Override
    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = new ExtensionTuples();

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = new HashMap<>(getAdditionalExtensionOccurences());

        // BasicConstraints
        ASN1ObjectIdentifier extensionType = Extension.basicConstraints;
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            BasicConstraints value = X509Util.createBasicConstraints(isCa(), getPathLenBasicConstraint());
            ExtensionTuple extension = createExtension(extensionType, occurence.isCritical(), value);
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // KeyUsage
        extensionType = Extension.keyUsage;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(getKeyUsage());
            ExtensionTuple extension = createExtension(extensionType, occurence.isCritical(), value);
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // ExtendedKeyUsage
        extensionType = Extension.extendedKeyUsage;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtendedKeyUsage value = X509Util.createExtendedUsage(getExtendedKeyUsages());
            ExtensionTuple extension = createExtension(extensionType, occurence.isCritical(), value);
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        return tuples;
    }

    protected static void checkAndAddExtension(ASN1ObjectIdentifier type, ExtensionOccurrence occurence,
            ExtensionTuple extension, ExtensionTuples tuples)
    throws CertProfileException
    {
        if(extension != null)
        {
            tuples.addExtension(extension);
        }
        else if(occurence.isRequired())
        {
            throw new CertProfileException("Could not add required extension " + type.getId());
        }
    }

    protected static ExtensionTuple createExtension(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value)
    throws CertProfileException
    {
        return (value == null) ? null : new ExtensionTuple(type, critical, value);
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return false;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier()
    {
        return ExtensionOccurrence.NONCRITICAL_REQUIRED;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfCRLDistributinPoints()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    protected Set<ASN1ObjectIdentifier> getExtendedKeyUsages()
    {
        return null;
    }

    @Override
    public void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
    }

    @Override
    public void initialize(String data)
    throws CertProfileException
    {
    }

    protected void verifySubjectDNOccurence(X500Name requestedSubject)
    throws BadCertTemplateException
    {
        verifySubjectDNOccurence(requestedSubject, null);
    }

    protected void verifySubjectDNOccurence(X500Name requestedSubject, Set<ASN1ObjectIdentifier> ignoreRDNs)
    throws BadCertTemplateException
    {
        Set<RDNOccurrence> occurences = getSubjectDNSubset();
        if(occurences == null)
        {
            return;
        }

        ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
        for(ASN1ObjectIdentifier type : types)
        {
            if(ignoreRDNs != null && ignoreRDNs.contains(type))
            {
                continue;
            }

            RDNOccurrence occu = null;
            for(RDNOccurrence occurence : occurences)
            {
                if(occurence.getType().equals(type))
                {
                    occu = occurence;
                    break;
                }
            }
            if(occu == null)
            {
                throw new BadCertTemplateException("Subject DN of type " + oidToDisplayName(type) + " is not allowed");
            }

            RDN[] rdns = requestedSubject.getRDNs(type);
            if(rdns.length > occu.getMaxOccurs() || rdns.length < occu.getMinOccurs())
            {
                throw new BadCertTemplateException("Occurrence of subject DN of type " + oidToDisplayName(type) +
                        " not within the allowed range. " + rdns.length +
                        " is not within [" +occu.getMinOccurs() + ", " + occu.getMaxOccurs() + "]");
            }
        }

        for(RDNOccurrence occurence : occurences)
        {
            if(occurence.getMinOccurs() == 0)
            {
                continue;
            }

            boolean present = false;
            for(ASN1ObjectIdentifier type : types)
            {
                if(occurence.getType().equals(type))
                {
                    present = true;
                    break;
                }
            }

            if(present == false)
            {
                throw new BadCertTemplateException("Requied subject DN of type " +
                        oidToDisplayName(occurence.getType()) + " is not present");
            }
        }
    }

    protected static String getSubjectFieldFirstValue(X500Name subject, ASN1ObjectIdentifier type, int index)
    {
        RDN[] rdns = subject.getRDNs(type);
        if(index < 0 || rdns == null || rdns.length <= index)
        {
            return null;
        }

        RDN rdn = rdns[index];
        return SecurityUtil.rdnValueToString(rdn.getFirst().getValue());
    }

    protected RDN createSubjectRDN(String text, ASN1ObjectIdentifier type)
    throws BadCertTemplateException
    {
        text = text.trim();
        ASN1Encodable dnValue;
        if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type) ||
                ObjectIdentifiers.DN_C.equals(type))
        {
            dnValue = new DERPrintableString(text);
        }
        else
        {
            dnValue = new DERUTF8String(text);
        }

        return new RDN(type, dnValue);
    }

    protected static String oidToDisplayName(ASN1ObjectIdentifier type)
    {
        return ObjectIdentifiers.oidToDisplayName(type);
    }

    protected static boolean isCountryCodeValid(String countryCode)
    {
        return countryCodes.contains(countryCode);
    }
}
