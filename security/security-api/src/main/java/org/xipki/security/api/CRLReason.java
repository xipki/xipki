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

package org.xipki.security.api;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The CRLReason enumeration specifies the reason that a certificate
 * is revoked, as defined in <a href="http://www.ietf.org/rfc/rfc3280.txt">
 * RFC 3280: Internet X.509 Public Key Infrastructure Certificate and CRL
 * Profile</a>.
 *
 * @author Lijun Liao
 */

public enum CRLReason
{
    /**
     * This reason indicates that it is unspecified as to why the
     * certificate has been revoked.
     */
    UNSPECIFIED (0, "unspecified"),

    /**
     * This reason indicates that it is known or suspected that the
     * certificate subject's private key has been compromised. It applies
     * to end-entity certificates only.
     */
    KEY_COMPROMISE (1, "keyCompromise"),

    /**
     * This reason indicates that it is known or suspected that the
     * certificate subject's private key has been compromised. It applies
     * to certificate authority (CA) certificates only.
     */
    CA_COMPROMISE(2, "cACompromise"),

    /**
     * This reason indicates that the subject's name or other information
     * has changed.
     */
    AFFILIATION_CHANGED(3, "affiliationChanged"),

    /**
     * This reason indicates that the certificate has been superseded.
     */
    SUPERSEDED(4, "superseded"),

    /**
     * This reason indicates that the certificate is no longer needed.
     */
    CESSATION_OF_OPERATION(5, "cessationOfOperation"),

    /**
     * This reason indicates that the certificate has been put on hold.
     */
    CERTIFICATE_HOLD(6, "certificateHold"),

    /**
     * This reason indicates that the certificate was previously on hold
     * and should be removed from the CRL. It is for use with delta CRLs.
     */
    REMOVE_FROM_CRL(8, "removeFromCRL"),

    /**
     * This reason indicates that the privileges granted to the subject of
     * the certificate have been withdrawn.
     */
    PRIVILEGE_WITHDRAWN(9, "privilegeWithdrawn"),

    /**
     * This reason indicates that it is known or suspected that the
     * certificate subject's private key has been compromised. It applies
     * to authority attribute (AA) certificates only.
     */
    AA_COMPROMISE(10, "aACompromise");

    public static List<CRLReason> PERMITTED_CLIENT_CRLREASONS = Collections.unmodifiableList(
        Arrays.asList(
            new CRLReason[]
            {
                CRLReason.UNSPECIFIED, CRLReason.KEY_COMPROMISE,
                CRLReason.AFFILIATION_CHANGED, CRLReason.SUPERSEDED,
                CRLReason.CESSATION_OF_OPERATION,
                CRLReason.CERTIFICATE_HOLD, CRLReason.PRIVILEGE_WITHDRAWN}));

    private final int code;
    private final String desription;

    private CRLReason(
            final int code,
            final String description)
    {
        this.code = code;
        this.desription = description;
    }

    public int getCode()
    {
        return code;
    }

    public String getDescription()
    {
        return desription;
    }

    private static Map<Integer, CRLReason> reasons = new HashMap<>();
    static
    {
        for(CRLReason value : CRLReason.values())
        {
            reasons.put(value.code, value);
        }
    }

    public static CRLReason forReasonCode(
            final int reasonCode)
    {
        return reasons.get(reasonCode);
    }

    public static CRLReason getInstance(
            final String text)
    {
        for(CRLReason value : values())
        {
            if(value.desription.equalsIgnoreCase(text)
                    || value.name().equalsIgnoreCase(text)
                    || Integer.toString(value.code).equals(text))
            {
                return value;
            }
        }

        return null;
    }
}
