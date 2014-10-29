/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.math.BigInteger;
import java.util.Date;

import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public class CertRevocationInfoWithSerial extends CertRevocationInfo
{
    private static final long serialVersionUID = 1L;
    private BigInteger serial;

    public CertRevocationInfoWithSerial(BigInteger serial, CRLReason reason,
            Date revocationTime, Date invalidityTime)
    {
        super(reason, revocationTime, invalidityTime);
        this.serial = serial;
    }

    public CertRevocationInfoWithSerial(BigInteger serial, int reasonCode,
            Date revocationTime, Date invalidityTime)
    {
        super(reasonCode, revocationTime, invalidityTime);
        this.serial = serial;
    }

    public BigInteger getSerial()
    {
        return serial;
    }

}
