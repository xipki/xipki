/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.io.InputStream;
import java.util.jar.Manifest;

/**
 * @author Lijun Liao
 */

final public class Version
{
    public static String PRODUCT_NAME = "XiPKI";

    public static void main(String []argv)
    {
        System.out.println(getVersion());
    }

    /**
     * @return the Maven Version, SVN Revision and Build timestamp as a human-readable String.
     */
    public static String getVersion()
    {
        StringBuilder version = new StringBuilder();

        try
        {
            InputStream is = Version.class.getResourceAsStream("/MANIFEST.MF");
            java.util.jar.Manifest   man    = new Manifest(is);
            java.util.jar.Attributes jattr  = man.getMainAttributes();
            // Copyright
            // Maven Version, SVN Revision, Build timestamp
            version.append(jattr.getValue("Implementation-Copyright")).append("\n");
            version.append("Version: ");
            version.append(jattr.getValue("Implementation-Version")).append(" ");
            version.append("Revision: ");
            version.append(jattr.getValue("Implementation-Build")).append(" ");
            version.append("Build at: ");
            version.append(jattr.getValue("Implementation-Build-Timestamp")).append(" ");
        }
        catch (Exception e)
        {
            return PRODUCT_NAME;
        }
        return version.toString();
    }

}

