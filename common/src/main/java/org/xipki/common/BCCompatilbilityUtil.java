/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Date;

import org.bouncycastle.asn1.cmp.PKIHeader;

/**
 * @author Lijun Liao
 */

public class BCCompatilbilityUtil
{
    private static Method pkiHeader_getMessageTime;

    static
    {
        try
        {
            pkiHeader_getMessageTime = PKIHeader.class.getMethod("getMessageTime");
        }catch(NoSuchMethodException e)
        {
        }
    }

    public static Date getMessageTime(PKIHeader pkiHeader)
    {
        if(pkiHeader_getMessageTime == null)
        {
            throw new RuntimeException("unsupported BouncyCastle version");
        }

        try
        {
            Object o = pkiHeader_getMessageTime.invoke(pkiHeader);
            if(o == null)
            {
                return null;
            }

            Method m = o.getClass().getMethod("getDate");
            return (Date) m.invoke(o);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException |
                NoSuchMethodException | SecurityException e)
        {
            throw new RuntimeException(e.getClass().getName() + ": " + e.getMessage(), e);
        }
    }

}
