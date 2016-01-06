/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.security.shell.p12;

import java.io.File;
import java.io.IOException;

import org.apache.karaf.shell.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.shell.KeyGenCmd;

/**
 * @author Lijun Liao
 */

public abstract class P12KeyGenCmd extends KeyGenCmd {
    @Option(name = "--subject", aliases = "-s",
            required = true,
            description = "subject in the self-signed certificate\n"
                    + "(required)")
    protected String subject;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the key\n"
                    + "(required)")
    protected String keyOutFile;

    @Option(name = "--cert-out",
            description = "where to save the self-signed certificate")
    protected String certOutFile;

    @Option(name = "--password",
            description = "password of the PKCS#12 file")
    protected String password;

    protected void saveKeyAndCert(
            final P12KeypairGenerationResult keyAndCert)
    throws IOException {
        File p12File = new File(keyOutFile);
        saveVerbose("saved PKCS#12 keystore to file", p12File, keyAndCert.getKeystore());
        if (certOutFile != null) {
            File certFile = new File(certOutFile);
            saveVerbose("saved self-signed certificate to file", certFile,
                    keyAndCert.getCertificate().getEncoded());
        }
    }

    protected char[] getPassword() {
        char[] pwdInChar = readPasswordIfNotSet(password);
        if (pwdInChar != null) {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

}
