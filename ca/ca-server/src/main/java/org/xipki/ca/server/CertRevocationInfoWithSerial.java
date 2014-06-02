/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server;

import java.math.BigInteger;
import java.util.Date;

import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;

public class CertRevocationInfoWithSerial extends CertRevocationInfo
{
    private final BigInteger serial;

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
