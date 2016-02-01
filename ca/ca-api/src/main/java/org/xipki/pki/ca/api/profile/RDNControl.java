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

package org.xipki.pki.ca.api.profile;

import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class RDNControl {

    private final int minOccurs;

    private final int maxOccurs;

    private final ASN1ObjectIdentifier type;

    private List<Pattern> patterns;

    private StringType stringType;

    private Range stringLengthRange;

    private String prefix;

    private String suffix;

    private String group;

    public RDNControl(
            final ASN1ObjectIdentifier type) {
        this(type, 1, 1);
    }

    public RDNControl(
            final ASN1ObjectIdentifier type,
            final int minOccurs,
            final int maxOccurs) {
        ParamUtil.assertNotNull("type", type);
        if (minOccurs < 0 || maxOccurs < 1 || minOccurs > maxOccurs) {
            throw new IllegalArgumentException(
                    String.format("illegal minOccurs=%s, maxOccurs=%s", minOccurs, maxOccurs));
        }
        this.type = type;
        this.minOccurs = minOccurs;
        this.maxOccurs = maxOccurs;
    }

    public int getMinOccurs() {
        return minOccurs;
    }

    public int getMaxOccurs() {
        return maxOccurs;
    }

    public ASN1ObjectIdentifier getType() {
        return type;
    }

    public StringType getStringType() {
        return stringType;
    }

    public List<Pattern> getPatterns() {
        return patterns;
    }

    public Range getStringLengthRange() {
        return stringLengthRange;
    }

    public void setStringType(
            final StringType stringType) {
        this.stringType = stringType;
    }

    public void setStringLengthRange(
            final Range stringLengthRange) {
        this.stringLengthRange = stringLengthRange;
    }

    public void setPatterns(
            final List<Pattern> patterns) {
        this.patterns = patterns;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(
            final String prefix) {
        this.prefix = prefix;
    }

    public String getSuffix() {
        return suffix;
    }

    public void setSuffix(
            final String suffix) {
        this.suffix = suffix;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(
            final String group) {
        this.group = group;
    }

}
