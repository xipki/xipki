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
