/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.rmi.UnexpectedException;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.pki.ca.server.mgmt.api.CAEntry;
import org.xipki.pki.ca.server.mgmt.shell.CaCmd;
import org.xipki.common.util.IoUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "enroll-cert",
        description = "enroll certificate")
public class EnrollCertCmd extends CaCmd
{
    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--p10",
            required = true,
            description = "PKCS#10 request file\n"
                    + "(required)")
    private String p10File;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the certificate\n"
                    + "(required)")
    private String outFile;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "profile name\n"
                    + "(required)")
    private String profileName;

    @Option(name = "--user",
            description = "username")
    private String user;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        CAEntry ca = caManager.getCA(caName);
        if (ca == null)
        {
            throw new UnexpectedException("CA " + caName + " not available");
        }

        byte[] encodedP10Request = IoUtil.read(p10File);

        X509Certificate cert = caManager.generateCertificate(caName, profileName, user,
                encodedP10Request);
        saveVerbose("saved certificate to file", new File(outFile), cert.getEncoded());

        return null;
    }

}
