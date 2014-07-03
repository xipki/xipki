/*
 * Copyright (c) 2014 Lijun Liao
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
            java.security.CodeSource cs     = Version.class.getProtectionDomain().getCodeSource();
            java.net.URL             jarLoc = cs.getLocation();
            java.util.jar.JarFile    jfile  = new java.util.jar.JarFile(new java.io.File(jarLoc.getFile()));
            java.util.jar.Manifest   man    = jfile.getManifest();
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
            jfile.close();
        }
        catch (Exception e)
        {
            return PRODUCT_NAME;
        }
        return version.toString();
    }

}

