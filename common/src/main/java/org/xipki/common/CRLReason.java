/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

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
                CRLReason.AFFILIATION_CHANGED, CRLReason.SUPERSEDED, CRLReason.CESSATION_OF_OPERATION,
                CRLReason.CERTIFICATE_HOLD,    CRLReason.PRIVILEGE_WITHDRAWN}));

    private final int code;
    private final String desription;

    private CRLReason(int code, String description)
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

    public static CRLReason forReasonCode(int reasonCode)
    {
        return reasons.get(reasonCode);
    }

    public static CRLReason getInstance(String text)
    {
        for(CRLReason value : values())
        {
            if(value.desription.equalsIgnoreCase(text) ||
                    value.name().equalsIgnoreCase(text) ||
                    Integer.toString(value.code).equals(text))
            {
                return value;
            }
        }

        return null;
    }
}
