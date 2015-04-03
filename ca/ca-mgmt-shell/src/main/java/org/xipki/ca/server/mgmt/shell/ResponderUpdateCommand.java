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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.X509Util;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "responder-up", description="update responder")
public class ResponderUpdateCommand extends CaCommand
{
    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "responder name\n"
                    + "(required)")
    private String name;

    @Option(name = "--signer-type",
            required = true,
            description = "type of the responder signer\n"
                    + "(required)")
    private String signerType;

    @Option(name = "--signer-conf",
            description = "conf of the responder signer or 'NULL'")
    private String signerConf;

    @Option(name = "--cert",
            description = "requestor certificate file or 'NULL'")
    private String certFile;

    private PasswordResolver passwordResolver;

    public void setPasswordResolver(
            final PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    @Override
    protected Object _doExecute()
    throws Exception
    {
        String cert = null;
        if(CAManager.NULL.equalsIgnoreCase(certFile))
        {
            cert = CAManager.NULL;
        }
        else if(certFile != null)
        {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            cert = Base64.toBase64String(certBytes);
        }

        if(signerConf != null)
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver);
        }

        boolean b = caManager.changeCmpResponder(name, signerType, signerConf, cert);
        output(b, "updated", "could not update", "CMP responder " + name);
        return null;
    }

}
