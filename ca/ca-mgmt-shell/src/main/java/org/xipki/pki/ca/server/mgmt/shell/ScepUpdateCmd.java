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

package org.xipki.pki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.pki.ca.server.mgmt.api.CAManager;
import org.xipki.pki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "scep-up",
        description = "Update SCEP")
public class ScepUpdateCmd extends CaCmd {
    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--resp-type",
            description = "type of the responder")
    private String responderType;

    @Option(name = "--resp-conf",
            description = "conf of the responder")
    private String responderConf;

    @Option(name = "--resp-cert",
            description = "responder certificate file or 'NULL'")
    private String certFile;

    @Option(name = "--control",
            description = "SCEP control or 'NULL'")
    private String control;

    private PasswordResolver passwordResolver;

    public void setPasswordResolver(
            final PasswordResolver passwordResolver) {
        this.passwordResolver = passwordResolver;
    }

    private String getResponderConf()
    throws Exception {
        if (responderConf == null) {
            return responderConf;
        }
        String _respType = responderType;
        if (_respType == null) {
            ScepEntry entry = caManager.getScepEntry(caName);
            if (entry == null) {
                throw new IllegalCmdParamException("please specify the responderType");
            }
            _respType = entry.getResponderType();
        }

        return ShellUtil.canonicalizeSignerConf(_respType, responderConf, passwordResolver);
    }

    @Override
    protected Object _doExecute()
    throws Exception {
        String certConf = null;
        if (CAManager.NULL.equalsIgnoreCase(certFile)) {
            certConf = CAManager.NULL;
        } else if (certFile != null) {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            certConf = Base64.toBase64String(certBytes);
        }

        ChangeScepEntry entry = new ChangeScepEntry(caName);
        if (responderType != null) {
            entry.setResponderType(responderType);
        }

        String conf = getResponderConf();
        if (conf != null) {
            entry.setResponderConf(conf);
        }

        if (certConf != null) {
            entry.setBase64Cert(certConf);
        }

        if (control != null) {
            entry.setControl(control);
        }

        boolean b = caManager.changeScep(entry);
        output(b, "updated", "could not update", "SCEP responder " + caName);
        return null;
    }
}
