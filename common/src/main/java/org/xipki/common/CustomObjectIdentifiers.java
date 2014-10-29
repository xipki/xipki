/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

/**
 * @author Lijun Liao
 */

public class CustomObjectIdentifiers
{
    private static final String id_private_dummy = "1.3.6.1.4.1.12655";
    public static final String id_crl_certset = id_private_dummy + ".100";
    public static final String id_cmp_generateCRL = id_private_dummy + ".101";
    public static final String id_cmp_getCmpResponderCert = id_private_dummy + ".102";
    public static final String id_cmp_getSystemInfo = id_private_dummy + ".103";
    public static final String id_cmp_removeExpiredCerts = id_private_dummy + ".104";
}
