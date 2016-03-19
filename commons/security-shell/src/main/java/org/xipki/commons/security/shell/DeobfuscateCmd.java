/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.commons.security.shell;

import java.io.File;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.password.api.OBFPasswordService;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "deobfuscate",
        description = "deobfuscate password")
@Service
public class DeobfuscateCmd extends SecurityCommandSupport {

    @Reference
    private OBFPasswordService obfPasswordService;

    @Option(name = "--password",
            description = "obfuscated password, starts with OBF:\n"
                    + "exactly one of password and password-file must be specified")
    private String passwordHint;

    @Option(name = "--password-file", description = "file containing the obfuscated password")
    @Completion(FilePathCompleter.class)
    private String passwordFile;

    @Option(name = "--out", description = "where to save the password")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    protected Object doExecute()
    throws Exception {
        if (!(passwordHint == null ^ passwordFile == null)) {
            throw new IllegalCmdParamException(
                    "exactly one of password and password-file must be specified");
        }

        if (passwordHint == null) {
            passwordHint = new String(IoUtil.read(passwordFile));
        }

        if (!StringUtil.startsWithIgnoreCase(passwordHint, "OBF:")) {
            throw new IllegalCmdParamException("encrypted password '" + passwordHint
                    + "' does not start with OBF:");
        }

        String password = obfPasswordService.deobfuscate(passwordHint);
        if (outFile != null) {
            saveVerbose("saved the password to file", new File(outFile),
                    new String(password).getBytes());
        } else {
            println("the password is: '" + new String(password) + "'");
        }
        return null;
    }

}
