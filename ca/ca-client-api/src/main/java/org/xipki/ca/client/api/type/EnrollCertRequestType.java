/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

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
