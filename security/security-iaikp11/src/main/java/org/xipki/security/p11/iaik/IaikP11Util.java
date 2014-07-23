/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.iaik;

import java.security.SecureRandom;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author Lijun Liao
 */

public class IaikP11Util
{

    public static byte[] generateKeyID(Session session)
    throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] keyID = null;
        do
        {
            keyID = new byte[8];
            random.nextBytes(keyID);
        } while(idExists(session, keyID));

        return keyID;
    }

    public static boolean idExists(Session session, byte[] keyID)
    throws Exception
    {
        Key k = new Key();
        k.getId().setByteArrayValue(keyID);

        session.findObjectsInit(k);
        Object[] objects = session.findObjects(1);
        session.findObjectsFinal();
        if (objects.length > 0)
        {
            return true;
        }

        X509PublicKeyCertificate c = new X509PublicKeyCertificate();
        c.getId().setByteArrayValue(keyID);

        session.findObjectsInit(c);
        objects = session.findObjects(1);
        session.findObjectsFinal();

        return objects.length > 0;
    }

    public static boolean labelExists(Session session, String keyLabel)
    throws Exception
    {
        Key k = new Key();
        k.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(k);
        Object[] objects = session.findObjects(1);
        session.findObjectsFinal();
        if (objects.length > 0)
        {
            return true;
        }

        X509PublicKeyCertificate c = new X509PublicKeyCertificate();
        c.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(c);
        objects = session.findObjects(1);
        session.findObjectsFinal();

        return objects.length > 0;
    }

    static String eraseSensitiveInfo(String data)
    {
        int index = data.indexOf("password");
        if(index == -1)
        {
            return data;
        }

        if(index > 1 && data.charAt(index - 1) == '%')
        {
            return data.substring(0, index - 1);
        }
        else
        {
            return data.substring(0, index);
        }
    }
}
