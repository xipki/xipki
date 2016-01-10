/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.profile.KeyParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.pki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.pki.ca.api.profile.RDNControl;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.StringType;
import org.xipki.common.LruCache;
import org.xipki.common.util.CollectionUtil;
import org.xipki.security.api.ObjectIdentifiers;
import org.xipki.security.api.util.SecurityUtil;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class BaseX509Certprofile extends X509Certprofile {

    private static final Logger LOG = LoggerFactory.getLogger(BaseX509Certprofile.class);

    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    protected abstract Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms();

    protected BaseX509Certprofile() {
    }

    protected String[] sortRDNs(
            final RDNControl control,
            final String[] values) {
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
     *
     * @return the subjectControl, could not be null.
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
        verifySubjectDNOccurence(requestedSubject);

        RDN[] requstedRDNs = requestedSubject.getRDNs();
        SubjectControl scontrol = getSubjectControl();

        List<RDN> rdns = new LinkedList<>();

        for (ASN1ObjectIdentifier type : scontrol.getTypes()) {
            RDNControl control = scontrol.getControl(type);
            if (control == null) {
                continue;
            }

            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = (thisRDNs == null)
                    ? 0
                    : thisRDNs.length;
            if (n == 0) {
                continue;
            }

            if (ObjectIdentifiers.DN_EmailAddress.equals(type)) {
                throw new BadCertTemplateException("emailAddress is not allowed");
            }

            if (n == 1) {
                ASN1Encodable rdnValue = thisRDNs[0].getFirst().getValue();
                RDN rdn;
                if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type)) {
                    rdn = createDateOfBirthRDN(type, rdnValue);
                } else if (ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type)) {
                    rdn = createPostalAddressRDN(type, rdnValue, control, 0);
                } else {
                    String value = X509Util.rdnValueToString(rdnValue);
                    rdn = createSubjectRDN(value, type, control, 0);
                }

                if (rdn != null) {
                    rdns.add(rdn);
                }
            } else {
                if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type)) {
                    for (int i = 0; i < n; i++) {
                        RDN rdn = createDateOfBirthRDN(type, thisRDNs[i].getFirst().getValue());
                        rdns.add(rdn);
                    }
                } else if (ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type)) {
                    for (int i = 0; i < n; i++) {
                        RDN rdn = createPostalAddressRDN(type, thisRDNs[i].getFirst().getValue(),
                                control, i);
                        rdns.add(rdn);
                    }
                } else {
                    String[] values = new String[n];
                    for (int i = 0; i < n; i++) {
                        values[i] = X509Util.rdnValueToString(thisRDNs[i].getFirst().getValue());
                    }
                    values = sortRDNs(control, values);

                    int i = 0;
                    for (String value : values) {
                        rdns.add(createSubjectRDN(value, type, control, i++));
                    }
                } // if
            } // if
        } // for

        Set<String> subjectDNGroups = scontrol.getGroups();
        if (CollectionUtil.isNotEmpty(subjectDNGroups)) {
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
        } // END for ()

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    private static RDN createDateOfBirthRDN(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable rdnValue)
    throws BadCertTemplateException {
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

        if (!SubjectDNSpec.p_dateOfBirth.matcher(text).matches()) {
            throw new BadCertTemplateException(
                    "Value of RDN dateOfBirth does not have format YYYMMDD000000Z");
        }

        if (newRdnValue == null) {
            newRdnValue = new DERGeneralizedTime(text);
        }

        return new RDN(type, newRdnValue);
    }

    private static RDN createPostalAddressRDN(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable rdnValue,
            final RDNControl control,
            final int index)
    throws BadCertTemplateException {
        if (!(rdnValue instanceof ASN1Sequence)) {
            throw new BadCertTemplateException("Value of RDN postalAddress has incorrect syntax");
        }

        ASN1Sequence seq = (ASN1Sequence) rdnValue;
        final int size = seq.size();
        if (size < 1 || size > 6) {
            throw new BadCertTemplateException(
                    "Sequence size of RDN postalAddress is not within [1, 6]: " + size);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < size; i++) {
            ASN1Encodable line = seq.getObjectAt(i);
            String text;
            if (line instanceof ASN1String && !(line instanceof DERUniversalString)) {
                text = ((ASN1String) line).getString();
            } else {
                throw new BadCertTemplateException("postalAddress[" + i + "] has incorrect syntax");
            }

            ASN1Encodable asn1Line = createRDNValue(text, type, control, index);
            v.add(asn1Line);
        }

        return new RDN(type, new DERSequence(v));
    }

    private static RDN[] getRDNs(
            final RDN[] rdns,
            final ASN1ObjectIdentifier type) {
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

    protected EnvParameterResolver parameterResolver;

    @Override
    public void setEnvParameterResolver(
            final EnvParameterResolver parameterResolver) {
        this.parameterResolver = parameterResolver;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists() {
        return false;
    }

    @Override
    public SubjectPublicKeyInfo checkPublicKey(
            final SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException {
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
                    throw new BadCertTemplateException("EC curve "
                            + SecurityUtil.getCurveName(curveOid)
                            + " (OID: " + curveOid.getId() + ") is not allowed");
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
                    throw new BadCertTemplateException("unaccepted EC point encoding "
                            + pointEncoding);
                }
            }

            byte[] keyData = publicKey.getPublicKeyData().getBytes();
            try {
                checkECSubjectPublicKeyInfo(curveOid, keyData);
            } catch (BadCertTemplateException e) {
                throw e;
            } catch (Exception e) {
                LOG.debug("populateFromPubKeyInfo", e);
                throw new BadCertTemplateException("invalid public key: " + e.getMessage());
            }
            return publicKey;
        } else if (keyParamsOption instanceof RSAParametersOption) {
            RSAParametersOption rsaOption = (RSAParametersOption) keyParamsOption;

            ASN1Integer modulus;
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(
                        publicKey.getPublicKeyData().getBytes());
                modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
            } catch (IllegalArgumentException e) {
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

            int pLength;
            int qLength;

            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(params);
                ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));
                ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(1));
                pLength = p.getPositiveValue().bitLength();
                qLength = q.getPositiveValue().bitLength();
            } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
                throw new BadCertTemplateException("illegal Dss-Parms");
            }

            boolean match = dsaOption.allowsPLength(pLength);
            if (match) {
                match = dsaOption.allowsQLength(qLength);
            }

            if (match) {
                return publicKey;
            }
        } else {
            throw new RuntimeException("should not reach here, unknown KeyParametersOption "
                    + keyParamsOption);
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    }

    @Override
    public void initialize(
            final String data)
    throws CertprofileException {
    }

    protected void verifySubjectDNOccurence(
            final X500Name requestedSubject)
    throws BadCertTemplateException {
        SubjectControl occurences = getSubjectControl();
        if (occurences == null) {
            return;
        }

        ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
        for (ASN1ObjectIdentifier type : types) {
            RDNControl occu = occurences.getControl(type);
            if (occu == null) {
                throw new BadCertTemplateException("subject DN of type "
                        + oidToDisplayName(type) + " is not allowed");
            }

            RDN[] rdns = requestedSubject.getRDNs(type);
            if (rdns.length > occu.getMaxOccurs() || rdns.length < occu.getMinOccurs()) {
                throw new BadCertTemplateException("occurrence of subject DN of type "
                        + oidToDisplayName(type)
                        + " not within the allowed range. " + rdns.length
                        + " is not within [" + occu.getMinOccurs() + ", "
                        + occu.getMaxOccurs() + "]");
            }
        }

        for (ASN1ObjectIdentifier m : occurences.getTypes()) {
            RDNControl occurence = occurences.getControl(m);
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
                throw new BadCertTemplateException("requied subject DN of type "
                        + oidToDisplayName(occurence.getType()) + " is not present");
            }
        }
    }

    protected RDN createSubjectRDN(
            final String text,
            final ASN1ObjectIdentifier type,
            final RDNControl option,
            final int index)
    throws BadCertTemplateException {
        ASN1Encodable rdnValue = createRDNValue(text, type, option, index);
        return (rdnValue == null)
                ? null
                : new RDN(type, rdnValue);
    }

    private static ASN1Encodable createRDNValue(
            final String text,
            final ASN1ObjectIdentifier type,
            final RDNControl option,
            final int index)
    throws BadCertTemplateException {
        String ttext = text.trim();

        if (option != null) {
            String prefix = option.getPrefix();
            String suffix = option.getSuffix();

            if (prefix != null || suffix != null) {
                String _text = ttext.toLowerCase();
                if (prefix != null && _text.startsWith(prefix.toLowerCase())) {
                    ttext = ttext.substring(prefix.length());
                    _text = ttext.toLowerCase();
                }

                if (suffix != null && _text.endsWith(suffix.toLowerCase())) {
                    ttext = ttext.substring(0, ttext.length() - suffix.length());
                }
            }

            List<Pattern> patterns = option.getPatterns();
            if (patterns != null) {
                Pattern p = patterns.get(index);
                if (!p.matcher(ttext).matches()) {
                    throw new BadCertTemplateException("invalid subject "
                            + ObjectIdentifiers.oidToDisplayName(type)
                            + " '" + ttext + "' against regex '" + p.pattern() + "'");
                }
            }

            StringBuilder sb = new StringBuilder();
            if (prefix != null) {
                sb.append(prefix);
            }
            sb.append(ttext);
            if (suffix != null) {
                sb.append(suffix);
            }
            ttext = sb.toString();

            int len = ttext.length();
            Range range = option.getStringLengthRange();
            Integer minLen = (range == null)
                    ? null
                    : range.getMin();

            if (minLen != null && len < minLen) {
                throw new BadCertTemplateException("subject "
                        + ObjectIdentifiers.oidToDisplayName(type)
                        + " '" + ttext + "' is too short (length (" + len
                        + ") < minLen (" + minLen + ")");
            }

            Integer maxLen = (range == null)
                    ? null
                    : range.getMax();

            if (maxLen != null && len > maxLen) {
                throw new BadCertTemplateException("subject "
                        + ObjectIdentifiers.oidToDisplayName(type)
                        + " '" + ttext + "' is too long (length (" + len
                        + ") > maxLen (" + maxLen + ")");
            }
        }

        StringType stringType = option.getStringType();
        if (stringType == null) {
            stringType = StringType.utf8String;
        }

        return stringType.createString(ttext.trim());
    }

    private static String oidToDisplayName(
            final ASN1ObjectIdentifier type) {
        return ObjectIdentifiers.oidToDisplayName(type);
    }

    private static void checkECSubjectPublicKeyInfo(
            final ASN1ObjectIdentifier curveOid,
            final byte[] encoded)
    throws BadCertTemplateException {
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
                throw new BadCertTemplateException("invalid point encoding 0x"
                        + Integer.toString(encoded[0], 16));
        }
    }

}
