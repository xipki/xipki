/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.shell.p12;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.xipki.common.util.ParamUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.shell.KeyGenAction;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12KeyGenAction extends KeyGenAction {

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the key\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password",
            description = "password of the keystore file")
    protected String password;

    protected void saveKey(final P12KeyGenerationResult keyGenerationResult) throws IOException {
        ParamUtil.requireNonNull("keyGenerationResult", keyGenerationResult);
        File p12File = new File(keyOutFile);
        saveVerbose("saved PKCS#12 keystore to file", p12File, keyGenerationResult.keystore());
    }

    protected KeystoreGenerationParameters getKeyGenParameters() throws IOException {
        KeystoreGenerationParameters params = new KeystoreGenerationParameters(
                getPassword());

        SecureRandom random = securityFactory.getRandom4Key();
        if (random != null) {
            params.setRandom(random);
        }

        return params;
    }

    private char[] getPassword() throws IOException {
        char[] pwdInChar = readPasswordIfNotSet(password);
        if (pwdInChar != null) {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

}
