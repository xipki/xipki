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

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.server.mgmt.api.ScepEntry;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.IoUtil;
import org.xipki.password.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "scep-add", description="add SCEP")
public class ScepAddCommand extends CaCommand
{
    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--resp-type",
            required = true,
            description = "type of the responder\n"
                    + "(required)")
    private String responderType;

    @Option(name = "--resp-conf",
            required = true,
            description = "conf of the responder\n"
                    + "(required)")
    private String responderConf;

    @Option(name = "--resp-cert",
            description = "responder certificate file")
    private String certFile;

    @Option(name = "--control",
            required = false,
            description = "SCEP control")
    private String scepControl;

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
        String base64Cert = null;
        if(certFile != null)
        {
            base64Cert= IoUtil.base64Encode(IoUtil.read(certFile), false);
        }

        if("PKCS12".equalsIgnoreCase(responderType) || "JKS".equalsIgnoreCase(responderType))
        {
            responderConf = ShellUtil.canonicalizeSignerConf(responderType, responderConf, passwordResolver);
        }

        ScepEntry entry = new ScepEntry(caName, responderType, responderConf, base64Cert, scepControl);
        if(entry.isFaulty())
        {
            throw new InvalidConfException("certificate is invalid");
        }

        boolean b = caManager.addScep(entry);
        output(b, "added", "could not add", "SCEP responder " + caName);
        return null;
    }
}
