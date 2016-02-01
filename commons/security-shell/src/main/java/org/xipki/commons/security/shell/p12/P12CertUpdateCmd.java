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

package org.xipki.commons.security.shell.p12;

import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */
@Command(scope = "xipki-tk", name = "update-cert-p12",
        description = "update certificate in PKCS#12 keystore")
@Service
public class P12CertUpdateCmd extends P12SecurityCommandSupport {

    @Option(name = "--cert",
            required = true,
            description = "certificate file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--ca-cert",
            multiValued = true,
            description = "CA Certificate file\n"
                    + "(multi-valued)")
    @Completion(FilePathCompleter.class)
    private Set<String> caCertFiles;

    @Override
    protected Object doExecute()
    throws Exception {
        KeyStore ks = getKeyStore();

        char[] pwd = getPassword();
        X509Certificate newCert = X509Util.parseCert(certFile);

        assertMatch(newCert, new String(pwd));

        String keyname = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                keyname = alias;
                break;
            }
        }

        if (keyname == null) {
            throw new SignerException("could not find private key");
        }

        Key key = ks.getKey(keyname, pwd);
        Set<X509Certificate> caCerts = new HashSet<>();
        if (isNotEmpty(caCertFiles)) {
            for (String caCertFile : caCertFiles) {
                caCerts.add(X509Util.parseCert(caCertFile));
            }
        }
        X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);

        ks.setKeyEntry(keyname, key, pwd, certChain);

        FileOutputStream fOut = null;
        try {
            fOut = new FileOutputStream(p12File);
            ks.store(fOut, pwd);
            out("updated certificate");
            return null;
        } finally {
            if (fOut != null) {
                fOut.close();
            }
        }
    }

    private void assertMatch(
            final X509Certificate cert,
            final String password)
    throws SignerException {
        ConfPairs pairs = new ConfPairs("keystore", "file:" + p12File);
        if (password != null) {
            pairs.putPair("password", new String(password));
        }

        securityFactory.createSigner("PKCS12", pairs.getEncoded(), "SHA1", null, cert);
    }

}
