/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.api.profile.x509;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.LruCache;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.profile.KeyParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.RdnControl;
import org.xipki.pki.ca.api.profile.StringType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class BaseX509Certprofile extends X509Certprofile {

    private static final Logger LOG = LoggerFactory.getLogger(BaseX509Certprofile.class);

    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    protected EnvParameterResolver envParameterResolver;

    protected BaseX509Certprofile() {
    }

    protected abstract Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms();

    protected String[] sortRdns(
            final RdnControl control,
            final String[] values) {
        ParamUtil.requireNonNull("values", values);

        if (control == null) {
            return values;
        }

        List<Pattern> patterns = control.getPatterns();
        if (CollectionUtil.isEmpty(patterns)) {
            return values;
        }

        List<String> result = new ArrayList<>(values.length);
        for (Pattern p : patterns) {
            for (String value : values) {
                if (!result.contains(value) && p.matcher(value).matches()) {
                    result.add(value);
                }
            }
        }
        for (String value : values) {
            if (!result.contains(value)) {
                result.add(value);
            }
        }

        return result.toArray(new String[0]);
    }

    /**
     * Get the SubjectControl.
     *
     * @return the subjectControl, must not be null.
     */
    protected abstract SubjectControl getSubjectControl();

    @Override
    public Date getNotBefore(
            final Date notBefore) {
        Date now = new Date();
        if (notBefore != null && notBefore.after(now)) {
            return notBefore;
        } else {
            return now;
        }
    }

    @Override
    public SubjectInfo getSubject(
            final X500Name requestedSubject)
    throws CertprofileException, BadCertTemplateException {
        ParamUtil.requireNonNull("requestedSubject", requestedSubject);

        verifySubjectDnOccurence(requestedSubject);

        RDN[] requstedRdns = requestedSubject.getRDNs();
        SubjectControl scontrol = getSubjectControl();

        List<RDN> rdns = new LinkedList<>();

        for (ASN1ObjectIdentifier type : scontrol.getTypes()) {
            RdnControl control = scontrol.getControl(type);
            if (control == null) {
                continue;
            }

            RDN[] thisRdns = getRdns(requstedRdns, type);
            int len = (thisRdns == null)
                    ? 0
                    : thisRdns.length;
            if (len == 0) {
                continue;
            }

            if (ObjectIdentifiers.DN_EmailAddress.equals(type)) {
                throw new BadCertTemplateException("emailAddress is not allowed");
            }

            if (len == 1) {
                ASN1Encodable rdnValue = thisRdns[0].getFirst().getValue();
                RDN rdn;
                if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type)) {
                    rdn = createDateOfBirthRdn(type, rdnValue);
                } else if (ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type)) {
                    rdn = createPostalAddressRdn(type, rdnValue, control, 0);
                } else {
                    String value = X509Util.rdnValueToString(rdnValue);
                    rdn = createSubjectRdn(value, type, control, 0);
                }

                if (rdn != null) {
                    rdns.add(rdn);
                }
            } else {
                if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type)) {
                    for (int i = 0; i < len; i++) {
                        RDN rdn = createDateOfBirthRdn(type, thisRdns[i].getFirst().getValue());
                        rdns.add(rdn);
                    }
                } else if (ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type)) {
                    for (int i = 0; i < len; i++) {
                        RDN rdn = createPostalAddressRdn(type, thisRdns[i].getFirst().getValue(),
                                control, i);
                        rdns.add(rdn);
                    }
                } else {
                    String[] values = new String[len];
                    for (int i = 0; i < len; i++) {
                        values[i] = X509Util.rdnValueToString(thisRdns[i].getFirst().getValue());
                    }
                    values = sortRdns(control, values);

                    int idx = 0;
                    for (String value : values) {
                        rdns.add(createSubjectRdn(value, type, control, idx++));
                    }
                } // if
            } // if
        } // for

        Set<String> subjectDnGroups = scontrol.getGroups();
        if (CollectionUtil.isNonEmpty(subjectDnGroups)) {
            Set<String> consideredGroups = new HashSet<>();
            final int n = rdns.size();

            List<RDN> newRdns = new ArrayList<>(rdns.size());
            for (int i = 0; i < n; i++) {
                RDN rdn = rdns.get(i);
                ASN1ObjectIdentifier type = rdn.getFirst().getType();
                String group = scontrol.getGroup(type);
                if (group == null) {
                    newRdns.add(rdn);
                } else if (!consideredGroups.contains(group)) {
                    List<AttributeTypeAndValue> atvs = new LinkedList<>();
                    atvs.add(rdn.getFirst());
                    for (int j = i + 1; j < n; j++) {
                        RDN rdn2 = rdns.get(j);
                        ASN1ObjectIdentifier type2 = rdn2.getFirst().getType();
                        String group2 = scontrol.getGroup(type2);
                        if (group.equals(group2)) {
                            atvs.add(rdn2.getFirst());
                        }
                    }

                    newRdns.add(new RDN(atvs.toArray(new AttributeTypeAndValue[0])));
                    consideredGroups.add(group);
                }
            } // for

            rdns = newRdns;
        } // if

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    } // method getSubject

    @Override
    public void setEnvParameterResolver(
            final EnvParameterResolver envParameterResolver) {
        this.envParameterResolver = envParameterResolver;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists() {
        return false;
    }

    @Override
    public SubjectPublicKeyInfo checkPublicKey(
            final SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("publicKey", publicKey);

        Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = getKeyAlgorithms();
        if (CollectionUtil.isEmpty(keyAlgorithms)) {
            return publicKey;
        }

        ASN1ObjectIdentifier keyType = publicKey.getAlgorithm().getAlgorithm();
        if (!keyAlgorithms.containsKey(keyType)) {
            throw new BadCertTemplateException("key type " + keyType.getId() + " is not permitted");
        }

        KeyParametersOption keyParamsOption = keyAlgorithms.get(keyType);
        if (keyParamsOption instanceof AllowAllParametersOption) {
            return publicKey;
        } else if (keyParamsOption instanceof ECParamatersOption) {
            ECParamatersOption ecOption = (ECParamatersOption) keyParamsOption;
            // parameters
            ASN1Encodable algParam = publicKey.getAlgorithm().getParameters();
            ASN1ObjectIdentifier curveOid;

            if (algParam instanceof ASN1ObjectIdentifier) {
                curveOid = (ASN1ObjectIdentifier) algParam;
                if (!ecOption.allowsCurve(curveOid)) {
                    throw new BadCertTemplateException(String.format(
                            "EC curve %s (OID: %s) is not allowed",
                            AlgorithmUtil.getCurveName(curveOid), curveOid.getId()));
                }
            } else {
                throw new BadCertTemplateException(
                        "only namedCurve or implictCA EC public key is supported");
            }

            // point encoding
            if (ecOption.getPointEncodings() != null) {
                byte[] keyData = publicKey.getPublicKeyData().getBytes();
                if (keyData.length < 1) {
                    throw new BadCertTemplateException("invalid publicKeyData");
                }
                byte pointEncoding = keyData[0];
                if (!ecOption.getPointEncodings().contains(pointEncoding)) {
                    throw new BadCertTemplateException(String.format(
                            "unaccepted EC point encoding '%s'", pointEncoding));
                }
            }

            byte[] keyData = publicKey.getPublicKeyData().getBytes();
            try {
                checkEcSubjectPublicKeyInfo(curveOid, keyData);
            } catch (BadCertTemplateException ex) {
                throw ex;
            } catch (Exception ex) {
                LOG.debug("populateFromPubKeyInfo", ex);
                throw new BadCertTemplateException(String.format(
                        "invalid public key: %s", ex.getMessage()));
            }
            return publicKey;
        } else if (keyParamsOption instanceof RSAParametersOption) {
            RSAParametersOption rsaOption = (RSAParametersOption) keyParamsOption;

            ASN1Integer modulus;
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(
                        publicKey.getPublicKeyData().getBytes());
                modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
            } catch (IllegalArgumentException ex) {
                throw new BadCertTemplateException("invalid publicKeyData");
            }

            int modulusLength = modulus.getPositiveValue().bitLength();
            if ((rsaOption.allowsModulusLength(modulusLength))) {
                return publicKey;
            }
        } else if (keyParamsOption instanceof DSAParametersOption) {
            DSAParametersOption dsaOption = (DSAParametersOption) keyParamsOption;
            ASN1Encodable params = publicKey.getAlgorithm().getParameters();
            if (params == null) {
                throw new BadCertTemplateException("null Dss-Parms is not permitted");
            }

            int plength;
            int qlength;

            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(params);
                ASN1Integer rsaP = ASN1Integer.getInstance(seq.getObjectAt(0));
                ASN1Integer rsaQ = ASN1Integer.getInstance(seq.getObjectAt(1));
                plength = rsaP.getPositiveValue().bitLength();
                qlength = rsaQ.getPositiveValue().bitLength();
            } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException ex) {
                throw new BadCertTemplateException("illegal Dss-Parms");
            }

            boolean match = dsaOption.allowsPlength(plength);
            if (match) {
                match = dsaOption.allowsQlength(qlength);
            }

            if (match) {
                return publicKey;
            }
        } else {
            throw new RuntimeException(String.format(
                    "should not reach here, unknown KeyParametersOption %s",
                    keyParamsOption));
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    } // method checkPublicKey

    @Override
    public void initialize(
            final String data)
    throws CertprofileException {
    }

    protected void verifySubjectDnOccurence(
            final X500Name requestedSubject)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("requestedSubject", requestedSubject);

        SubjectControl occurences = getSubjectControl();
        if (occurences == null) {
            return;
        }

        ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
        for (ASN1ObjectIdentifier type : types) {
            RdnControl occu = occurences.getControl(type);
            if (occu == null) {
                throw new BadCertTemplateException(String.format(
                        "subject DN of type %s is not allowed", oidToDisplayName(type)));
            }

            RDN[] rdns = requestedSubject.getRDNs(type);
            if (rdns.length > occu.getMaxOccurs() || rdns.length < occu.getMinOccurs()) {
                throw new BadCertTemplateException(String.format(
                        "occurrence of subject DN of type %s not within the allowed range. "
                        + "%d is not within [%d, %d]",
                        oidToDisplayName(type),
                        rdns.length,
                        occu.getMinOccurs(),
                        occu.getMaxOccurs()));
            }
        }

        for (ASN1ObjectIdentifier m : occurences.getTypes()) {
            RdnControl occurence = occurences.getControl(m);
            if (occurence.getMinOccurs() == 0) {
                continue;
            }

            boolean present = false;
            for (ASN1ObjectIdentifier type : types) {
                if (occurence.getType().equals(type)) {
                    present = true;
                    break;
                }
            }

            if (!present) {
                throw new BadCertTemplateException(String.format(
                        "requied subject DN of type %s is not present",
                        oidToDisplayName(occurence.getType())));
            }
        }
    } // method verifySubjectDnOccurence

    protected RDN createSubjectRdn(
            final String text,
            final ASN1ObjectIdentifier type,
            final RdnControl option,
            final int index)
    throws BadCertTemplateException {
        ASN1Encodable rdnValue = createRdnValue(text, type, option, index);
        return (rdnValue == null)
                ? null
                : new RDN(type, rdnValue);
    }

    private static RDN createDateOfBirthRdn(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable rdnValue)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("type", type);

        String text;
        ASN1Encodable newRdnValue = null;
        if (rdnValue instanceof ASN1GeneralizedTime) {
            text = ((ASN1GeneralizedTime) rdnValue).getTimeString();
            newRdnValue = rdnValue;
        } else if (rdnValue instanceof ASN1String && !(rdnValue instanceof DERUniversalString)) {
            text = ((ASN1String) rdnValue).getString();
        } else {
            throw new BadCertTemplateException("Value of RDN dateOfBirth has incorrect syntax");
        }

        if (!SubjectDnSpec.PATTERN_DATE_OF_BIRTH.matcher(text).matches()) {
            throw new BadCertTemplateException(
                    "Value of RDN dateOfBirth does not have format YYYMMDD000000Z");
        }

        if (newRdnValue == null) {
            newRdnValue = new DERGeneralizedTime(text);
        }

        return new RDN(type, newRdnValue);
    }

    private static RDN createPostalAddressRdn(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable rdnValue,
            final RdnControl control,
            final int index)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("type", type);

        if (!(rdnValue instanceof ASN1Sequence)) {
            throw new BadCertTemplateException(
                    "rdnValue of RDN postalAddress has incorrect syntax");
        }

        ASN1Sequence seq = (ASN1Sequence) rdnValue;
        final int size = seq.size();
        if (size < 1 || size > 6) {
            throw new BadCertTemplateException(
                    "Sequence size of RDN postalAddress is not within [1, 6]: " + size);
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < size; i++) {
            ASN1Encodable line = seq.getObjectAt(i);
            String text;
            if (line instanceof ASN1String && !(line instanceof DERUniversalString)) {
                text = ((ASN1String) line).getString();
            } else {
                throw new BadCertTemplateException(
                    String.format("postalAddress[%d] has incorrect syntax", i));
            }

            ASN1Encodable asn1Line = createRdnValue(text, type, control, index);
            vec.add(asn1Line);
        }

        return new RDN(type, new DERSequence(vec));
    }

    private static RDN[] getRdns(
            final RDN[] rdns,
            final ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("rdns", rdns);
        ParamUtil.requireNonNull("type", type);

        List<RDN> ret = new ArrayList<>(1);
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];
            if (rdn.getFirst().getType().equals(type)) {
                ret.add(rdn);
            }
        }

        return CollectionUtil.isEmpty(ret)
                ? null
                : ret.toArray(new RDN[0]);
    }

    private static ASN1Encodable createRdnValue(
            final String text,
            final ASN1ObjectIdentifier type,
            final RdnControl option,
            final int index)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("text", text);
        ParamUtil.requireNonNull("type", type);

        String tmpText = text.trim();

        StringType stringType = null;

        if (option != null) {
            stringType = option.getStringType();
            String prefix = option.getPrefix();
            String suffix = option.getSuffix();

            if (prefix != null || suffix != null) {
                String locTmpText = tmpText.toLowerCase();
                if (prefix != null && locTmpText.startsWith(prefix.toLowerCase())) {
                    tmpText = tmpText.substring(prefix.length());
                    locTmpText = tmpText.toLowerCase();
                }

                if (suffix != null && locTmpText.endsWith(suffix.toLowerCase())) {
                    tmpText = tmpText.substring(0, tmpText.length() - suffix.length());
                }
            }

            List<Pattern> patterns = option.getPatterns();
            if (patterns != null) {
                Pattern pattern = patterns.get(index);
                if (!pattern.matcher(tmpText).matches()) {
                    throw new BadCertTemplateException(
                        String.format("invalid subject %s '%s' against regex '%s'",
                                ObjectIdentifiers.oidToDisplayName(type),
                                tmpText, pattern.pattern()));
                }
            }

            StringBuilder sb = new StringBuilder();
            if (prefix != null) {
                sb.append(prefix);
            }
            sb.append(tmpText);
            if (suffix != null) {
                sb.append(suffix);
            }
            tmpText = sb.toString();

            int len = tmpText.length();
            Range range = option.getStringLengthRange();
            Integer minLen = (range == null)
                    ? null
                    : range.getMin();

            if (minLen != null && len < minLen) {
                throw new BadCertTemplateException(
                    String.format("subject %s '%s' is too short (length (%d) < minLen (%d))",
                        ObjectIdentifiers.oidToDisplayName(type), tmpText, len, minLen));
            }

            Integer maxLen = (range == null)
                    ? null
                    : range.getMax();

            if (maxLen != null && len > maxLen) {
                throw new BadCertTemplateException(
                        String.format("subject %s '%s' is too long (length (%d) > maxLen (%d))",
                                ObjectIdentifiers.oidToDisplayName(type), tmpText, len, maxLen));
            }
        }

        if (stringType == null) {
            stringType = StringType.utf8String;
        }

        return stringType.createString(tmpText.trim());
    } // method createRdnValue

    private static String oidToDisplayName(
            final ASN1ObjectIdentifier type) {
        return ObjectIdentifiers.oidToDisplayName(type);
    }

    private static void checkEcSubjectPublicKeyInfo(
            final ASN1ObjectIdentifier curveOid,
            final byte[] encoded)
    throws BadCertTemplateException {
        ParamUtil.requireNonNull("curveOid", curveOid);
        ParamUtil.requireNonNull("encoded", encoded);
        ParamUtil.requireMin("encoded.length", encoded.length, 1);

        Integer expectedLength = ecCurveFieldSizes.get(curveOid);
        if (expectedLength == null) {
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(curveOid);
            ECCurve curve = ecP.getCurve();
            expectedLength = (curve.getFieldSize() + 7) / 8;
            ecCurveFieldSizes.put(curveOid, expectedLength);
        }

        switch (encoded[0]) {
        case 0x02: // compressed
        case 0x03: // compressed
            if (encoded.length != (expectedLength + 1)) {
                throw new BadCertTemplateException("incorrect length for compressed encoding");
            }
            break;
        case 0x04: // uncompressed
        case 0x06: // hybrid
        case 0x07: // hybrid
            if (encoded.length != (2 * expectedLength + 1)) {
                throw new BadCertTemplateException(
                        "incorrect length for uncompressed/hybrid encoding");
            }
            break;
        default:
            throw new BadCertTemplateException(
                    String.format("invalid point encoding 0x%02x", encoded[0]));
        }
    } // method checkEcSubjectPublicKeyInfo

}
