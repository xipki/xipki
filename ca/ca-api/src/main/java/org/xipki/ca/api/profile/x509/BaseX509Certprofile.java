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

package org.xipki.ca.api.profile.x509;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.profile.DirectoryStringType;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.ca.api.profile.RDNControl;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.common.LruCache;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

public abstract class BaseX509Certprofile
extends X509Certprofile
{
    private static final Logger LOG = LoggerFactory.getLogger(BaseX509Certprofile.class);
    private static Set<String> countryCodes;
    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

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

    protected abstract Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms();

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

    protected BaseX509Certprofile()
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

    public Set<RDNControl> getSubjectDNControls()
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
    throws CertprofileException, BadCertTemplateException
    {
        verifySubjectDNOccurence(requestedSubject);
        checkSubjectContent(requestedSubject);

        RDN[] requstedRDNs = requestedSubject.getRDNs();
        Set<RDNControl> controls = getSubjectDNControls();
        List<RDN> rdns = new LinkedList<>();
        List<ASN1ObjectIdentifier> types = backwardsSubject() ?
                ObjectIdentifiers.getBackwardDNs() : ObjectIdentifiers.getForwardDNs();

        for(ASN1ObjectIdentifier type : types)
        {
            RDNControl control = null;
            if(controls != null)
            {
                control = getRDNControl(controls, type);
                if(control == null || control.getMaxOccurs() < 1)
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
                rdns.add(createSubjectRDN(value, type, control, 0));
            }
            else
            {
                String[] values = new String[n];
                for(int i = 0; i < n; i++)
                {
                    values[i] = SecurityUtil.rdnValueToString(thisRDNs[i].getFirst().getValue());
                }
                values = sortRDNs(type, values);

                int index = 0;
                for(String value : values)
                {
                    rdns.add(createSubjectRDN(value, type, control, index++));
                }
            }
        }

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    protected static RDNControl getRDNControl(Set<RDNControl> controls, ASN1ObjectIdentifier type)
    {
        for(RDNControl control : controls)
        {
            if(control.getType().equals(type))
            {
                return control;
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

        return CollectionUtil.isEmpty(ret) ? null : ret.toArray(new RDN[0]);
    }

    protected EnvironmentParameterResolver parameterResolver;
    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        this.parameterResolver = parameterResolver;
    }

    protected static void checkAndAddExtension(ASN1ObjectIdentifier type, ExtensionControl occurence,
            ExtensionValue value, ExtensionValues values)
    throws CertprofileException
    {
        if(value != null)
        {
            values.addExtension(type, value);
        }
        else if(occurence.isRequired())
        {
            throw new CertprofileException("Could not add required extension " + type.getId());
        }
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return false;
    }

    @Override
    public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = getKeyAlgorithms();
        if(CollectionUtil.isEmpty(keyAlgorithms))
        {
            return publicKey;
        }

        ASN1ObjectIdentifier keyType = publicKey.getAlgorithm().getAlgorithm();
        if(keyAlgorithms.containsKey(keyType) == false)
        {
            throw new BadCertTemplateException("key type " + keyType.getId() + " is not permitted");
        }

        KeyParametersOption keyParamsOption = keyAlgorithms.get(keyType);
        if(keyParamsOption instanceof AllowAllParametersOption)
        {
            return publicKey;
        } else if(keyParamsOption instanceof ECParamatersOption)
        {
            ECParamatersOption ecOption = (ECParamatersOption) keyParamsOption;
            // parameters
            ASN1Encodable algParam = publicKey.getAlgorithm().getParameters();
            ASN1ObjectIdentifier curveOid;

            if(algParam instanceof ASN1ObjectIdentifier)
            {
                curveOid = (ASN1ObjectIdentifier) algParam;
                if(ecOption.allowsCurve(curveOid) == false)
                {
                    throw new BadCertTemplateException("EC curve " + SecurityUtil.getCurveName(curveOid) +
                            " (OID: " + curveOid.getId() + ") is not allowed");
                }
            } else
            {
                throw new BadCertTemplateException("Only namedCurve or implictCA EC public key is supported");
            }

            // point encoding
            if(ecOption.getPointEncodings() != null)
            {
                byte[] keyData = publicKey.getPublicKeyData().getBytes();
                if(keyData.length < 1)
                {
                    throw new BadCertTemplateException("invalid publicKeyData");
                }
                byte pointEncoding = keyData[0];
                if(ecOption.getPointEncodings().contains(pointEncoding) == false)
                {
                    throw new BadCertTemplateException("Unaccepted EC point encoding " + pointEncoding);
                }
            }

            byte[] keyData = publicKey.getPublicKeyData().getBytes();
            try
            {
                checkECSubjectPublicKeyInfo(curveOid, keyData);
            }catch(BadCertTemplateException e)
            {
                throw e;
            }catch(Exception e)
            {
                LOG.debug("populateFromPubKeyInfo", e);
                throw new BadCertTemplateException("Invalid public key: " + e.getMessage());
            }
            return publicKey;
        } else if(keyParamsOption instanceof RSAParametersOption)
        {
            RSAParametersOption rsaOption = (RSAParametersOption) keyParamsOption;

            ASN1Integer modulus;
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(publicKey.getPublicKeyData().getBytes());
                modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
            }catch(IllegalArgumentException e)
            {
                throw new BadCertTemplateException("invalid publicKeyData");
            }

            int modulusLength = modulus.getPositiveValue().bitLength();
            if((rsaOption.allowsModulusLength(modulusLength)))
            {
                return publicKey;
            }
        } else if(keyParamsOption instanceof DSAParametersOption)
        {
            DSAParametersOption dsaOption = (DSAParametersOption) keyParamsOption;
            ASN1Encodable params = publicKey.getAlgorithm().getParameters();
            if(params == null)
            {
                throw new BadCertTemplateException("null Dss-Parms is not permitted");
            }

            int pLength;
            int qLength;

            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(params);
                ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));
                ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(1));
                pLength = p.getPositiveValue().bitLength();
                qLength = q.getPositiveValue().bitLength();
            } catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e)
            {
                throw new BadCertTemplateException("illegal Dss-Parms");
            }

            boolean match = dsaOption.allowsPLength(pLength);
            if(match)
            {
                match = dsaOption.allowsQLength(qLength);
            }

            if(match)
            {
                return publicKey;
            }
        } else
        {
            throw new RuntimeException("should not reach here, unknown KeyParametersOption " + keyParamsOption);
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    }

    @Override
    public void initialize(String data)
    throws CertprofileException
    {
    }

    protected void verifySubjectDNOccurence(X500Name requestedSubject)
    throws BadCertTemplateException
    {
        Set<RDNControl> occurences = getSubjectDNControls();
        if(occurences == null)
        {
            return;
        }

        ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
        for(ASN1ObjectIdentifier type : types)
        {
            RDNControl occu = null;
            for(RDNControl occurence : occurences)
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

        for(RDNControl occurence : occurences)
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

    protected RDN createSubjectRDN(String text, ASN1ObjectIdentifier type, RDNControl rdnControl, int index)
    throws BadCertTemplateException
    {
        DirectoryStringType dsEnum = rdnControl == null ? null : rdnControl.getDirectoryStringEnum();
        if(dsEnum == null)
        {
            if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type) ||
                    ObjectIdentifiers.DN_C.equals(type))
            {
                dsEnum = DirectoryStringType.printableString;
            }
            else
            {
                dsEnum = DirectoryStringType.utf8String;
            }
        }

        text = text.trim();
        ASN1Encodable dnValue = dsEnum.createDirectoryString(text);
        return new RDN(type, dnValue);
    }

    protected static String oidToDisplayName(ASN1ObjectIdentifier type)
    {
        return ObjectIdentifiers.oidToDisplayName(type);
    }

    public static boolean isCountryCodeValid(String countryCode)
    {
        return countryCodes.contains(countryCode);
    }

    private static void checkECSubjectPublicKeyInfo(ASN1ObjectIdentifier curveOid, byte[] encoded)
    throws BadCertTemplateException
    {
        Integer expectedLength = ecCurveFieldSizes.get(curveOid);
        if(expectedLength == null)
        {
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(curveOid);
            ECCurve curve = ecP.getCurve();
            expectedLength = (curve.getFieldSize() + 7) / 8;
            ecCurveFieldSizes.put(curveOid, expectedLength);
        }

        switch (encoded[0])
        {
            case 0x02: // compressed
            case 0x03: // compressed
            {
                if (encoded.length != (expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for compressed encoding");
                }
                break;
            }
            case 0x04: // uncompressed
            case 0x06: // hybrid
            case 0x07: // hybrid
            {
                if (encoded.length != (2 * expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for uncompressed/hybrid encoding");
                }
                break;
            }
            default:
                throw new BadCertTemplateException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
        }
    }

}
