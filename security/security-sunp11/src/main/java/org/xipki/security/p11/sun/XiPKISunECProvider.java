/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.sun;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * @author Lijun Liao
 */

public class XiPKISunECProvider extends Provider
{
    private static final long serialVersionUID = 1L;
    public static final String NAME = "XiPKI-SunEC";
    public static final double VERSION = 1.0;

    public XiPKISunECProvider()
    {
        super(NAME, VERSION, NAME + " (version " + VERSION + ")");

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                put("AlgorithmParameters.EC", ECParameters.class.getName());
                return null;
            }
        });
    }
}
