/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

/**
 * SHOULD NOT BE USED IN PRODUCTION ENVIRONMENT. ONLY FOR TEST PURPOSE
 *
 * @author Lijun Liao
 */

public class DummyPBEPasswordResolver extends PBEPasswordResolver
{

    private char[] masterPassword;

    protected char[] getMasterPassword()
    {
        if(masterPassword != null)
        {
            return masterPassword;
        }

        return super.getMasterPassword();
    }
    public void setMasterPassword(char[] masterPassword)
    {
        this.masterPassword = masterPassword;
    }

}
