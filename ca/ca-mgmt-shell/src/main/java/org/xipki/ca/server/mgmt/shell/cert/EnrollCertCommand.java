/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.shell.CaCommand;
import org.xipki.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "enroll-cert", description="Enroll certificate")
public class EnrollCertCommand extends CaCommand
{
    private static final Logger LOG = LoggerFactory.getLogger(EnrollCertCommand.class);

    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-p10",
            required = true, description = "Required. PKCS#10 request file")
    protected String p10File;

    @Option(name = "-out",
            description = "Required. Where to save the certificate",
            required = true)
    protected String outFile;

    @Option(name = "-profile",
            required = true, description = "Required. Profile name")
    protected String profileName;

    @Option(name = "-user",
            required = false, description = "Username")
    protected String user;

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509CAEntry ca = caManager.getCA(caName);
        if(ca == null)
        {
            err("CA " + caName + " not available");
            return null;
        }

        byte[] encodedP10Request = IoCertUtil.read(p10File);

        try
        {
            X509Certificate cert = caManager.generateCertificate(caName, profileName, user, encodedP10Request);
            saveVerbose("Saved certificate to file", new File(outFile), cert.getEncoded());
        } catch (Exception e)
        {
            LOG.warn("Exception: {}", e.getMessage());
            LOG.debug("Exception", e);
            err("ERROR: " + e.getMessage());
            return null;
        }

        return null;
    }

}
