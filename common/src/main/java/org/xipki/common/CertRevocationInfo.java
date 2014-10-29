/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Lijun Liao
 */

public class CertRevocationInfo implements Serializable
{
    private CRLReason reason;
    private Date revocationTime;
    private Date invalidityTime;

    public CertRevocationInfo(CRLReason reason)
    {
        this(reason, null, null);
    }

    public CertRevocationInfo(int reasonCode)
    {
        this(reasonCode, null, null);
    }

    public CertRevocationInfo(CRLReason reason, Date revocationTime, Date invalidityTime)
    {
        ParamChecker.assertNotNull("reason", reason);
        ParamChecker.assertNotNull("revocationTime", revocationTime);
        this.reason = reason;
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
        this.serialVersion = SERIAL_VERSION;
    }

    public CertRevocationInfo(int reasonCode, Date revocationTime, Date invalidityTime)
    {
        ParamChecker.assertNotNull("revocationTime", revocationTime);

        this.reason = CRLReason.forReasonCode(reasonCode);
        if(this.reason == null)
        {
            throw new IllegalArgumentException("invalid reason " + reasonCode);
        }
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
        this.serialVersion = SERIAL_VERSION;
    }

    public void setReason(CRLReason reason)
    {
        ParamChecker.assertNotNull("reason", reason);
        this.reason = reason;
    }

    public CRLReason getReason()
    {
        return reason;
    }

    public void setRevocationTime(Date revocationTime)
    {
        this.revocationTime = revocationTime;
    }

    /**
     *
     * @return revocation time, never be null
     */
    public Date getRevocationTime()
    {
        if(revocationTime == null)
        {
            revocationTime = new Date();
        }
        return revocationTime;
    }

    /**
     *
     * @return invalidity time, may be null
     */
    public Date getInvalidityTime()
    {
        return invalidityTime;
    }

    public void setInvalidityTime(Date invalidityTime)
    {
        this.invalidityTime = invalidityTime;
    }

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_reason= "reason";
    private static final String SR_revocationTime = "revocationTime";
    private static final String SR_invalidityTime = "invalidityTime";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_reason, reason);
        serialMap.put(SR_revocationTime, revocationTime);
        serialMap.put(SR_invalidityTime, invalidityTime);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);
        reason = (CRLReason) serialMap.get(SR_reason);
        revocationTime = (Date) serialMap.get(SR_revocationTime);
        invalidityTime = (Date) serialMap.get(SR_invalidityTime);
    }

}
