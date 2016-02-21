/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.shell.p12;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.api.p12.P12KeypairGenerationResult;
import org.xipki.commons.security.api.p12.P12KeypairGenerator;
import org.xipki.commons.security.api.p12.P12KeystoreGenerationParameters;
import org.xipki.commons.security.shell.KeyGenCommandSupport;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12KeyGenCommandSupport extends KeyGenCommandSupport {

    @Reference
    protected P12KeypairGenerator keyGenerator;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the key\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password",
            description = "password of the PKCS#12 file")
    protected String password;

    protected void saveKeypair(
            final P12KeypairGenerationResult keypair)
    throws IOException {
        File p12File = new File(keyOutFile);
        saveVerbose("saved PKCS#12 keystore to file", p12File, keypair.getKeystore());
    }

    protected P12KeystoreGenerationParameters getKeyGenParameters() {
        P12KeystoreGenerationParameters params = new P12KeystoreGenerationParameters(
                getPassword());

        SecureRandom random = securityFactory.getRandom4Key();
        if (random != null) {
            params.setRandom(random);
        }

        return params;
    }

    private char[] getPassword() {
        char[] pwdInChar = readPasswordIfNotSet(password);
        if (pwdInChar != null) {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

}
