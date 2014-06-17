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

package org.xipki.ca.cmp.client.type;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.xipki.security.common.ParamChecker;

public class EnrollCertRequestType
{
    public static enum Type
    {
        CERT_REQ,
        KEY_UPDATE,
        CROSS_CERT_REQ;
    }

    private final Type type;
    private final List<EnrollCertRequestEntryType> requestEntries = new LinkedList<>();

    public EnrollCertRequestType(Type type)
    {
        ParamChecker.assertNotNull("type", type);
        this.type = type;
    }

    public Type getType()
    {
        return type;
    }

    public boolean addRequestEntry(EnrollCertRequestEntryType requestEntry)
    {
        String id = requestEntry.getId();
        ASN1Integer certReqId = requestEntry.getCertReq().getCertReqId();
        for(EnrollCertRequestEntryType re : requestEntries)
        {
            if(re.getId().equals(id))
            {
                return false;
            }

            if(re.getCertReq().getCertReqId().equals(certReqId))
            {
                return false;
            }
        }

        requestEntries.add(requestEntry);
        return true;
    }

    public List<EnrollCertRequestEntryType> getRequestEntries()
    {
        return Collections.unmodifiableList(requestEntries);
    }
}
