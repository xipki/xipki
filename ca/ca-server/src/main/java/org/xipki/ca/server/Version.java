/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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

