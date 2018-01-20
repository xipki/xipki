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

package org.xipki.password.callback;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.OBFPasswordService;
import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class FilePasswordCallback implements PasswordCallback {

    private static final Logger LOG = LoggerFactory.getLogger(FilePasswordCallback.class);

    private String passwordFile;

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
        if (passwordFile == null) {
            throw new PasswordResolverException("please initialize me first");
        }

        String passwordHint = null;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(IoUtil.expandFilepath(passwordFile)));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (StringUtil.isNotBlank(line) && !line.startsWith("#")) {
                    passwordHint = line;
                    break;
                }
            }
        } catch (IOException ex) {
            throw new PasswordResolverException("could not read file " + passwordFile, ex);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ex) {
                    LOG.error("could not close reader: {}", ex.getMessage());
                }
            }
        }

        if (passwordHint == null) {
            throw new PasswordResolverException("no password is specified in file " + passwordFile);
        }

        if (StringUtil.startsWithIgnoreCase(passwordHint, OBFPasswordService.OBFUSCATE)) {
            return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
        } else {
            return passwordHint.toCharArray();
        }
    } // method getPassword

    @Override
    public void init(String conf) throws PasswordResolverException {
        ParamUtil.requireNonBlank("conf", conf);
        ConfPairs pairs = new ConfPairs(conf);
        passwordFile = pairs.value("file");
        if (StringUtil.isBlank(passwordFile)) {
            throw new PasswordResolverException("invalid configuration " + conf
                    + ", no file is specified");
        }
        passwordFile = IoUtil.expandFilepath(passwordFile);
    }

}
