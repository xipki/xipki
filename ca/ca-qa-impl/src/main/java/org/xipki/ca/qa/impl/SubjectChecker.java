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

package org.xipki.ca.qa.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.profile.RDNControl;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.api.profile.StringType;
import org.xipki.ca.api.profile.x509.SubjectControl;
import org.xipki.ca.api.profile.x509.SubjectDNSpec;
import org.xipki.ca.certprofile.XmlX509CertprofileUtil;
import org.xipki.ca.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.qa.ValidationIssue;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.X509Util;

/**
 * @author Lijun Liao
 */

public class SubjectChecker
{
    private final String specialBehavior;

    private final SubjectControl subjectControl;

    public SubjectChecker(
            final X509ProfileType conf)
    throws CertprofileException
    {
        this.specialBehavior = conf.getSpecialBehavior();

        Subject subject = conf.getSubject();

        Map<ASN1ObjectIdentifier, RDNControl> subjectDNControls = new HashMap<>();

        for(RdnType t : subject.getRdn())
        {
            StringType stringType = XmlX509CertprofileUtil.convertStringType(
                    t.getStringType());
            ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(t.getType().getValue());

            List<Pattern> patterns = null;
            if(CollectionUtil.isNotEmpty(t.getRegex()))
            {
                patterns = new LinkedList<>();
                for(String regex : t.getRegex())
                {
                    Pattern pattern = Pattern.compile(regex);
                    patterns.add(pattern);
                }
            }

            if(patterns == null)
            {
                Pattern pattern = SubjectDNSpec.getPattern(type);
                if(pattern != null)
                {
                    patterns = Arrays.asList(pattern);
                }
            }

            Range range;
            if(t.getMinLen() != null || t.getMaxLen() != null)
            {
                range = new Range(t.getMinLen(), t.getMaxLen());
            }
            else
            {
                range = null;
            }

            RDNControl rdnControl = new RDNControl(type, t.getMinOccurs(), t.getMaxOccurs());
            rdnControl.setStringType(stringType);
            rdnControl.setStringLengthRange(range);
            rdnControl.setPatterns(patterns);
            rdnControl.setPrefix(t.getPrefix());
            rdnControl.setSuffix(t.getSuffix());
            rdnControl.setGroup(t.getGroup());
            SubjectDNSpec.fixRDNControl(rdnControl);

            subjectDNControls.put(type, rdnControl);
        }
        this.subjectControl = new SubjectControl(subject.isDnBackwards(), subjectDNControls);

    }

    public List<ValidationIssue> checkSubject(
            final X500Name subject,
            final X500Name requestedSubject)
    {
        ParamChecker.assertNotNull("subject", subject);
        ParamChecker.assertNotNull("requestedSubject", requestedSubject);

        // collect subject attribute types to check
        Set<ASN1ObjectIdentifier> oids = new HashSet<>();

        for(ASN1ObjectIdentifier oid : subjectControl.getTypes())
        {
            oids.add(oid);
        }

        for(ASN1ObjectIdentifier oid : subject.getAttributeTypes())
        {
            oids.add(oid);
        }

        List<ValidationIssue> result = new LinkedList<>();

        ValidationIssue issue = new ValidationIssue("X509.SUBJECT.group", "X509 subject RDN group");
        result.add(issue);
        if(CollectionUtil.isNotEmpty(subjectControl.getGroups()))
        {
            Set<String> groups = new HashSet<>(subjectControl.getGroups());
            for(String g : groups)
            {
                boolean toBreak = false;
                RDN rdn = null;
                for(ASN1ObjectIdentifier type : subjectControl.getTypesForGroup(g))
                {
                    RDN[] rdns = subject.getRDNs(type);
                    if(rdns == null || rdns.length == 0)
                    {
                        continue;
                    }

                    if(rdns.length > 1)
                    {
                        issue.setFailureMessage("AttributeTypeAndValues of group " + g + " is not in one RDN");
                        toBreak = true;
                        break;
                    }

                    if(rdn == null)
                    {
                        rdn = rdns[0];
                    }
                    else if(rdn != rdns[0])
                    {
                        issue.setFailureMessage("AttributeTypeAndValues of group " + g + " is not in one RDN");
                        toBreak = true;
                        break;
                    }
                }

                if(toBreak)
                {
                    break;
                }
            }
        }

        for(ASN1ObjectIdentifier type : oids)
        {
            ValidationIssue valIssue;
            try
            {
                valIssue = checkSubjectAttribute(type, subject, requestedSubject);
            } catch (BadCertTemplateException e)
            {
                valIssue = new ValidationIssue("X509.SUBJECT.REQUEST", "Subject in request");
                valIssue.setFailureMessage(e.getMessage());
            }
            result.add(valIssue);
        }

        return result;
    }

    private ValidationIssue checkSubjectAttribute(
            final ASN1ObjectIdentifier type,
            final X500Name subject,
            final X500Name requestedSubject)
    throws BadCertTemplateException
    {
        boolean multiValuedRdn = subjectControl.getGroup(type) != null;
        if(multiValuedRdn)
        {
            return checkSubjectAttributeMultiValued(type, subject, requestedSubject);
        }
        else
        {
            return checkSubjectAttributeNotMultiValued(type, subject, requestedSubject);
        }
    }

    private ValidationIssue checkSubjectAttributeNotMultiValued(
            final ASN1ObjectIdentifier type,
            final X500Name subject,
            final X500Name requestedSubject)
    throws BadCertTemplateException
    {
        ValidationIssue issue = createSubjectIssue(type);

        // control
        int minOccurs;
        int maxOccurs;
        RDNControl rdnControl = subjectControl.getControl(type);
        if(rdnControl == null)
        {
            minOccurs = 0;
            maxOccurs = 0;
        } else
        {
            minOccurs = rdnControl.getMinOccurs();
            maxOccurs = rdnControl.getMaxOccurs();
        }
        RDN[] rdns = subject.getRDNs(type);
        int rdnsSize = rdns == null ? 0 : rdns.length;

        if(rdnsSize < minOccurs || rdnsSize > maxOccurs)
        {
            issue.setFailureMessage("number of RDNs '" + rdnsSize +
                    "' is not within [" + minOccurs + ", " + maxOccurs + "]");
            return issue;
        }

        RDN[] requestedRdns = requestedSubject.getRDNs(type);

        if(rdnsSize == 0)
        {
            // check optional attribute but is present in requestedSubject
            if(maxOccurs > 0 && requestedRdns != null && requestedRdns.length > 0)
            {
                issue.setFailureMessage("is absent but expected present");
            }
            return issue;
        }

        StringBuilder failureMsg = new StringBuilder();

        // check the encoding
        StringType stringType = rdnControl.getStringType();

        List<String> requestedCoreAtvTextValues = new LinkedList<>();
        if(requestedRdns != null)
        {
            for(RDN requestedRdn : requestedRdns)
            {
                String textValue = getRdnTextValueOfRequest(requestedRdn);
                requestedCoreAtvTextValues.add(textValue);
            }

            if(rdnControl != null && rdnControl.getPatterns() != null)
            {
                // sort the requestedRDNs
                requestedCoreAtvTextValues = sort(requestedCoreAtvTextValues, rdnControl.getPatterns());
            }
        }

        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
            if(atvs.length > 1)
            {
                failureMsg.append("size of RDN[" + i + "] is '" + atvs.length + "' but expected '1'");
                failureMsg.append("; ");
                continue;
            }

            String atvTextValue = getAtvValueString("RDN[" + i + "]", atvs[0], stringType, failureMsg);
            if(atvTextValue == null)
            {
                continue;
            }

            checkAttributeTypeAndValue("RDN[" + i + "]", type,
                    atvTextValue, rdnControl, requestedCoreAtvTextValues, i, failureMsg);
        }

        int n = failureMsg.length();
        if(n > 2)
        {
            failureMsg.delete(n - 2, n);
            issue.setFailureMessage(failureMsg.toString());
        }

        return issue;
    }

    private ValidationIssue checkSubjectAttributeMultiValued(
            final ASN1ObjectIdentifier type,
            final X500Name subject,
            final X500Name requestedSubject)
    throws BadCertTemplateException
    {
        ValidationIssue issue = createSubjectIssue(type);

        // control        
        int minOccurs;
        int maxOccurs;
        RDNControl rdnControl = subjectControl.getControl(type);
        if(rdnControl == null)
        {
            minOccurs = 0;
            maxOccurs = 0;
        } else
        {
            minOccurs = rdnControl.getMinOccurs();
            maxOccurs = rdnControl.getMaxOccurs();
        }

        RDN[] rdns = subject.getRDNs(type);
        int rdnsSize = rdns == null ? 0 : rdns.length;

        RDN[] requestedRdns = requestedSubject.getRDNs(type);

        if(rdnsSize != 1)
        {
            if(rdnsSize == 0)
            {
                // check optional attribute but is present in requestedSubject
                if(requestedRdns != null && requestedRdns.length > 0)
                {
                    issue.setFailureMessage("is absent but expected present");
                }
            }
            else
            {
                issue.setFailureMessage("number of RDNs '" + rdnsSize +
                        "' is not 1");
            }
            return issue;
        }

        // check the encoding
        StringType stringType = rdnControl.getStringType();
        List<String> requestedCoreAtvTextValues = new LinkedList<>();
        if(requestedRdns != null)
        {
            for(RDN requestedRdn : requestedRdns)
            {
                String textValue = getRdnTextValueOfRequest(requestedRdn);
                requestedCoreAtvTextValues.add(textValue);
            }

            if(rdnControl != null && rdnControl.getPatterns() != null)
            {
                // sort the requestedRDNs
                requestedCoreAtvTextValues = sort(requestedCoreAtvTextValues, rdnControl.getPatterns());
            }
        }

        StringBuilder failureMsg = new StringBuilder();

        AttributeTypeAndValue[] l = rdns[0].getTypesAndValues();
        List<AttributeTypeAndValue> atvs = new LinkedList<>();
        for(AttributeTypeAndValue m : l)
        {
            if(type.equals(m.getType()))
            {
                atvs.add(m);
            }
        }

        final int atvsSize = atvs.size();
        if(atvsSize < minOccurs || atvsSize > maxOccurs)
        {
            issue.setFailureMessage("number of AttributeTypeAndValuess '" + atvsSize +
                    "' is not within [" + minOccurs + ", " + maxOccurs + "]");
            return issue;
        }

        for(int i = 0; i < atvsSize; i++)
        {
            AttributeTypeAndValue atv = atvs.get(i);
            String atvTextValue = getAtvValueString("AttributeTypeAndValue[" + i + "]", atv, stringType, failureMsg);
            if(atvTextValue == null)
            {
                continue;
            }

            checkAttributeTypeAndValue("AttributeTypeAndValue[" + i + "]", type,
                    atvTextValue, rdnControl, requestedCoreAtvTextValues, i, failureMsg);
        }

        int n = failureMsg.length();
        if(n > 2)
        {
            failureMsg.delete(n - 2, n);
            issue.setFailureMessage(failureMsg.toString());
        }

        return issue;
    }

    private static List<String> sort(
            final List<String> contentList,
            final List<Pattern> patternList)
    {
        List<String> sorted = new ArrayList<>(contentList.size());
        for(Pattern p : patternList)
        {
            for(String value : contentList)
            {
                if(sorted.contains(value) == false && p.matcher(value).matches())
                {
                    sorted.add(value);
                }
            }
        }
        for(String value : contentList)
        {
            if(sorted.contains(value) == false)
            {
                sorted.add(value);
            }
        }
        return sorted;
    }

    private static boolean matchStringType(
            final ASN1Encodable atvValue,
            final StringType stringType)
    {
        boolean correctStringType = true;
        switch(stringType)
        {
        case bmpString:
            correctStringType = (atvValue instanceof DERBMPString);
            break;
        case printableString:
            correctStringType = (atvValue instanceof DERPrintableString);
            break;
        case teletexString:
            correctStringType = (atvValue instanceof DERT61String);
            break;
        case utf8String:
            correctStringType = (atvValue instanceof DERUTF8String);
            break;
        case ia5String:
            correctStringType = (atvValue instanceof DERIA5String);
            break;
        default:
            throw new RuntimeException("should not reach here, unknown StringType " + stringType);
        } // end switch
        return correctStringType;
    }

    private static String getRdnTextValueOfRequest(
            final RDN requestedRdn)
    throws BadCertTemplateException
    {
        ASN1ObjectIdentifier type = requestedRdn.getFirst().getType();
        ASN1Encodable v = requestedRdn.getFirst().getValue();
        if(ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type))
        {
            if(v instanceof ASN1GeneralizedTime == false)
            {
                throw new BadCertTemplateException("requested RDN is not of GeneralizedTime");
            }
            return ((ASN1GeneralizedTime) v).getTimeString();
        }
        else if(ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type))
        {
            if(v instanceof ASN1Sequence == false)
            {
                throw new BadCertTemplateException("requested RDN is not of Sequence");
            }

            ASN1Sequence seq = (ASN1Sequence) v;
            final int n = seq.size();

            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < n; i++)
            {
                ASN1Encodable o = seq.getObjectAt(i);
                String textValue = X509Util.rdnValueToString(o);
                sb.append("[").append(i).append("]=").append(textValue).append(",");
            }

            return sb.toString();
        }
        else
        {
            return X509Util.rdnValueToString(v);
        }
    }

    private static ValidationIssue createSubjectIssue(
            final ASN1ObjectIdentifier subjectAttrType)
    {
        ValidationIssue issue;
        String attrName = ObjectIdentifiers.getName(subjectAttrType);
        if(attrName == null)
        {
            attrName = subjectAttrType.getId().replace('.', '_');
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "attribute " + subjectAttrType.getId());
        }
        else
        {
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "extension " + attrName +
                    " (" + subjectAttrType.getId() + ")");
        }
        return issue;
    }

    private static String getAtvValueString(
            final String name,
            final AttributeTypeAndValue atv,
            final StringType stringType,
            final StringBuilder failureMsg)
    {
        ASN1ObjectIdentifier type = atv.getType();
        ASN1Encodable atvValue = atv.getValue();

        if(ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type))
        {
            if(atvValue instanceof ASN1GeneralizedTime == false)
            {
                failureMsg.append(name).append(" is not of type GeneralizedTime");
                failureMsg.append("; ");
                return null;
            }
            return ((ASN1GeneralizedTime) atvValue).getTimeString();
        }
        else if(ObjectIdentifiers.DN_POSTAL_ADDRESS.equals(type))
        {
            if(atvValue instanceof ASN1Sequence == false)
            {
                failureMsg.append(name).append(" is not of type Sequence");
                failureMsg.append("; ");
                return null;
            }

            ASN1Sequence seq = (ASN1Sequence) atvValue;
            final int n = seq.size();

            StringBuilder sb = new StringBuilder();
            boolean validEncoding = true;
            for(int i = 0; i < n; i++)
            {
                ASN1Encodable o = seq.getObjectAt(i);
                if(matchStringType(o, stringType) == false)
                {
                    failureMsg.append(name).append(".[" + i + "] is not of type " + stringType.name());
                    failureMsg.append("; ");
                    validEncoding = false;
                    break;
                }

                String textValue = X509Util.rdnValueToString(o);
                sb.append("[").append(i).append("]=").append(textValue).append(",");
            }

            if(validEncoding == false)
            {
                return null;
            }

            return sb.toString();
        }
        else
        {
            if(matchStringType(atvValue, stringType) == false)
            {
                failureMsg.append(name).append(" is not of type " + stringType.name());
                failureMsg.append("; ");
                return null;
            }

            return X509Util.rdnValueToString(atvValue);
        }
    }

    private void checkAttributeTypeAndValue(
            final String name,
            final ASN1ObjectIdentifier type,
            final String _atvTextValue,
            final RDNControl rdnControl,
            final List<String> requestedCoreAtvTextValues,
            final int index,
            final StringBuilder failureMsg)
    throws BadCertTemplateException
    {
        String atvTextValue = _atvTextValue;
        if(ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(type))
        {
            if(SubjectDNSpec.p_dateOfBirth.matcher(atvTextValue).matches() == false)
            {
                throw new BadCertTemplateException("Value of RDN dateOfBirth does not have format YYYMMDD000000Z");
            }
        }
        else if(rdnControl != null)
        {
            String prefix = rdnControl.getPrefix();
            if(prefix != null)
            {
                if(atvTextValue.startsWith(prefix) == false)
                {
                    failureMsg.append(name).append(" '").append(atvTextValue).
                        append("' does not start with prefix '").append(prefix).append("'");
                    failureMsg.append("; ");
                    return;
                }
                else
                {
                    atvTextValue = atvTextValue.substring(prefix.length());
                }
            }

            String suffix = rdnControl.getSuffix();
            if(suffix != null)
            {
                if(atvTextValue.endsWith(suffix) == false)
                {
                    failureMsg.append(name).append(" '").append(atvTextValue)
                            .append("' does not end with suffx '").append(suffix).append("'");
                    failureMsg.append("; ");
                    return;
                }
                else
                {
                    atvTextValue = atvTextValue.substring(0, atvTextValue.length() - suffix.length());
                }
            }

            List<Pattern> patterns = rdnControl.getPatterns();
            if(patterns != null)
            {
                Pattern pattern = patterns.get(index);
                boolean matches = pattern.matcher(atvTextValue).matches();
                if(matches == false)
                {
                    failureMsg.append(name).append(" '").append(atvTextValue)
                            .append("' is not valid against regex '").append(pattern.pattern()).append("'");
                    failureMsg.append("; ");
                    return;
                }
            }
        }

        if(CollectionUtil.isEmpty(requestedCoreAtvTextValues))
        {
            if(type.equals(ObjectIdentifiers.DN_SERIALNUMBER) == false)
            {
                failureMsg.append("is present but not contained in the request");
                failureMsg.append("; ");
            }
        }
        else
        {
            String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(index);
            if(ObjectIdentifiers.DN_CN.equals(type) &&
                    specialBehavior != null &&
                    "gematik_gSMC_K".equals(specialBehavior))
            {
                if(atvTextValue.startsWith(requestedCoreAtvTextValue + "-") == false)
                {
                    failureMsg.append("content '").append(atvTextValue).append("' does not start with '")
                            .append(requestedCoreAtvTextValue).append("-'");
                    failureMsg.append("; ");
                }
            }
            else if(type.equals(ObjectIdentifiers.DN_SERIALNUMBER))
            {
            }
            else
            {
                if(atvTextValue.equals(requestedCoreAtvTextValue) == false)
                {
                    failureMsg.append("content '").append(atvTextValue).append("' but expected '")
                            .append(requestedCoreAtvTextValue).append("'");
                    failureMsg.append("; ");
                }
            }
        }
    }
}
