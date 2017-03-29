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

package org.xipki.commons.security.shell;

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
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.shell.completer.KeystoreTypeCompleter;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xipki-tk", name = "convert-keystore",
        description = "Convert keystore")
@Service
public class ConvertKeystoreCmd extends SecurityCommandSupport {

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
    protected Object doExecute() throws Exception {
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
