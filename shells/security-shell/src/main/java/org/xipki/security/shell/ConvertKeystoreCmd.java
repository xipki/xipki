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

package org.xipki.security.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.shell.completer.KeystoreTypeCompleter;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xi", name = "convert-keystore",
        description = "Convert keystore")
@Service
public class ConvertKeystoreCmd extends SecurityAction {

    @Option(name = "--in",
            required = true,
            description = "Source keystore file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(name = "--intype",
            required = true,
            description = "Type of the source keystore\n"
                    + "(required)")
    @Completion(KeystoreTypeCompleter.class)
    private String inType;

    @Option(name = "--inpwd",
            description = "password of the source keystore")
    private String inPwd;

    @Option(name = "--out",
            required = true,
            description = "Destination keystore file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(name = "--outtype",
            required = true,
            description = "Type of the destination keystore\n"
                    + "(required)")
    @Completion(KeystoreTypeCompleter.class)
    private String outType;

    @Option(name = "--outpwd",
            description = "password of the destination keystore")
    private String outPwd;

    @Override
    protected Object execute0() throws Exception {
        File realInFile = new File(IoUtil.expandFilepath(inFile));
        File realOutFile = new File(IoUtil.expandFilepath(outFile));

        if (CompareUtil.equalsObject(realInFile, realOutFile)) {
            throw new IllegalCmdParamException("in and out cannot be the same");
        }

        KeyStore inKs = KeyStore.getInstance(inType);
        KeyStore outKs = KeyStore.getInstance(outType);
        outKs.load(null);

        char[] inPassword = readPasswordIfNotSet("password of the source keystore", inPwd);
        FileInputStream inStream = new FileInputStream(realInFile);
        try {
            inKs.load(inStream, inPassword);
        } finally {
            inStream.close();
        }

        char[] outPassword = readPasswordIfNotSet("password of the destination keystore", outPwd);
        Enumeration<String> aliases = inKs.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (inKs.isKeyEntry(alias)) {
                Certificate[] certs = inKs.getCertificateChain(alias);
                Key key = inKs.getKey(alias, inPassword);
                outKs.setKeyEntry(alias, key, outPassword, certs);
            } else {
                Certificate cert = inKs.getCertificate(alias);
                outKs.setCertificateEntry(alias, cert);
            }
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
        outKs.store(bout, outPassword);
        saveVerbose("saved destination keystore to file", realOutFile, bout.toByteArray());
        return null;
    }

}
