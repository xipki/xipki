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
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.shell.completer.KeystoreTypeCompleter;
import org.xipki.commons.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.1.1
 */

@Command(scope = "xipki-tk", name = "import-cert",
        description = "Import certificates to a keystore")
@Service
public class ImportCertCmd extends SecurityCommandSupport {

    @Option(name = "--keystore",
            required = true,
            description = "Keystore file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String ksFile;

    @Option(name = "--type",
            required = true,
            description = "Type of the keystore\n"
                    + "(required)")
    @Completion(KeystoreTypeCompleter.class)
    private String ksType;

    @Option(name = "--password",
            description = "password of the keystore")
    private String ksPwd;

    @Option(name = "--cert", aliases = "-c",
            required = true, multiValued = true,
            description = "Certificate files\n"
                    + "(required, multi-valued)")
    private List<String> certFiles;

    @Override
    protected Object doExecute() throws Exception {
        File realKsFile = new File(IoUtil.expandFilepath(ksFile));
        KeyStore ks = KeyStore.getInstance(ksType);
        char[] password = readPasswordIfNotSet(ksPwd);

        Set<String> aliases = new HashSet<>(10);
        if (realKsFile.exists()) {
            FileInputStream inStream = new FileInputStream(realKsFile);
            try {
                ks.load(inStream, password);
            } finally {
                inStream.close();
            }

            Enumeration<String> strs = ks.aliases();
            while (strs.hasMoreElements()) {
                aliases.add(strs.nextElement());
            }
        } else {
            ks.load(null);
        }

        for (String certFile : certFiles) {
            X509Certificate cert = X509Util.parseCert(certFile);
            String baseAlias = X509Util.getCommonName(cert.getSubjectX500Principal());
            String alias = baseAlias;
            int idx = 2;
            while (aliases.contains(alias)) {
                alias = baseAlias + "-" + (idx++);
            }
            ks.setCertificateEntry(alias, cert);
            aliases.add(alias);
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
        ks.store(bout, password);
        saveVerbose("saved keystore to file", realKsFile, bout.toByteArray());
        return null;
    }

}
