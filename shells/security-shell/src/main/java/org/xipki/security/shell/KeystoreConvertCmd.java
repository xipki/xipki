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
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "keystore-convert",
        description = "convert the keystore format")
@Service
public class KeystoreConvertCmd extends SecurityAction {

    @Option(name = "--in-type", required = true,
            description = "type of source keystore\n(required)")
    private String inType;

    @Option(name = "--in", required = true,
            description = "file of source keystore\n(required)")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(name = "--in-provider",
            description = "Security provider of source keystore")
    private String inProvider;

    @Option(name = "--in-pass",
            description = "password of source keystore")
    private String inPass;

    @Option(name = "--in-keypass-diff",
            description = "whether the password for the keys differs from that of source keystore\n"
                + "will be ignored if --in-keypass is set")
    private Boolean inKeyPassDiff = Boolean.FALSE;

    @Option(name = "--in-keypass",
            description = "password for the keys of source keystore\n"
                    + "Default to the keystore password")
    private String inKeyPass;

    @Option(name = "--out-type", required = true,
            description = "type of target keystore\n(required)")
    private String outType;

    @Option(name = "--out-provider",
            description = "Security provider of target keystore")
    private String outProvider;

    @Option(name = "--out", required = true,
            description = "file of target keystore\n(required)")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(name = "--out-pass",
            description = "password of target keystore")
    private String outPass;

    @Option(name = "--out-keypass-diff",
            description = "whether the password for the keys differs from that of target keystore\n"
                    + "will be ignored if --out-keypass is set")
    private Boolean outKeyPassDiff = Boolean.FALSE;

    @Option(name = "--out-keypass",
            description = "password for the keys of target keystore\n"
                    + "Default to the keystore password")
    private String outKeyPass;

    @Override
    protected Object execute0() throws Exception {
        KeyStore srcKs;
        if (StringUtil.isBlank(inProvider)) {
            srcKs = KeyStore.getInstance(inType);
        } else {
            srcKs = KeyStore.getInstance(inType, inProvider);
        }

        char[] inPwd;
        if (inPass != null) {
            inPwd = inPass.toCharArray();
        } else {
            inPwd = readPassword("Enter the password of the source keystore");
        }

        srcKs.load(new FileInputStream(inFile), inPwd);
        Enumeration<String> aliases = srcKs.aliases();
        boolean containsKeyEntry = false;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (srcKs.isKeyEntry(alias)) {
                containsKeyEntry = true;
                break;
            }
        }

        char[] inKeyPwd = null;
        if (containsKeyEntry) {
            if (inKeyPass != null) {
                inKeyPwd = inKeyPass.toCharArray();
            } else {
                if (inKeyPassDiff) {
                    inKeyPwd = readPassword("Enter the password for keys of the source keystore");
                } else {
                    inKeyPwd = inPwd;
                }
            }
        }

        char[] outPwd;
        if (outPass != null) {
            outPwd = outPass.toCharArray();
        } else {
            outPwd = readPassword("Enter the password of the target keystore");
        }

        char[] outKeyPwd = null;
        if (containsKeyEntry) {
            if (outKeyPass != null) {
                inKeyPwd = outKeyPass.toCharArray();
            } else {
                if (outKeyPassDiff) {
                    inKeyPwd = readPassword("Enter the password for keys of the target keystore");
                } else {
                    inKeyPwd = inPwd;
                }
            }
        }

        KeyStore destKs;
        if (StringUtil.isBlank(outProvider)) {
            destKs = KeyStore.getInstance(outType);
        } else {
            destKs = KeyStore.getInstance(outType, inProvider);
        }

        destKs.load(null, outPwd);

        aliases = srcKs.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (srcKs.isKeyEntry(alias)) {
                Key key = srcKs.getKey(alias, inKeyPwd);
                Certificate[] chain = srcKs.getCertificateChain(alias);
                destKs.setKeyEntry(alias, key, outKeyPwd, chain);
            } else if (srcKs.isCertificateEntry(alias)) {
                Certificate cert = srcKs.getCertificate(alias);
                destKs.setCertificateEntry(alias, cert);
            } else {
                println("entry " + alias + " is neither key nor certificate, ignore it");
            }
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        destKs.store(bout, outPwd);

        saveVerbose("converted keystore to", new File(outFile), bout.toByteArray());
        return null;
    }

}
