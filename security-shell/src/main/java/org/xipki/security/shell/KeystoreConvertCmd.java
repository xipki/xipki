/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.util.KeyUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "keystore-convert",
        description = "convert the keystore format")
@Service
public class KeystoreConvertCmd extends SecurityCommandSupport {

    @Option(name = "--in-type",
            required = true,
            description = "type of source keystore\n"
                    + "(required)")
    private String inType;

    @Option(name = "--in",
            required = true,
            description = "file of source keystore\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String inFile;

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

    @Option(name = "--out-type",
            required = true,
            description = "type of target keystore\n"
                    + "(required)")
    private String outType;

    @Option(name = "--out",
            required = true,
            description = "file of target keystore\n"
                    + "(required)")
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
    protected Object doExecute() throws Exception {
        KeyStore srcKs = KeyUtil.getKeyStore(inType);

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

        KeyStore destKs = KeyUtil.getKeyStore(outType);
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
