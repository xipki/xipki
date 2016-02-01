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

package org.xipki.pki.ca.jscep.client.shell;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.jscep.client.Client;
import org.jscep.client.verification.PreProvisionedCertificateVerifier;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class ClientCommandSupport extends XipkiCommandSupport {

    @Option(name = "--url",
            required = true,
            description = "URL of the SCEP server\n"
                    + "(required)")
    private String url;

    @Option(name = "--ca-id",
            description = "CA identifier")
    private String caId;

    @Option(name = "--ca-cert",
            required = true,
            description = "CA certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String caCertFile;

    @Option(name = "--p12",
            required = true,
            description = "PKCS#12 keystore file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(name = "--password",
            description = "password of the PKCS#12 file")
    private String password;

    private Client scepClient;
    private PrivateKey identityKey;
    private X509Certificate identityCert;

    protected Client getScepClient()
    throws CertificateException, IOException {
        if (scepClient == null) {
            X509Certificate caCert = X509Util.parseCert(caCertFile);
            URL _url = new URL(url);
            scepClient = new Client(_url, new PreProvisionedCertificateVerifier(caCert));
        }
        return scepClient;
    }

    protected PrivateKey getIdentityKey()
    throws Exception {
        if (identityKey == null) {
            readIdentity();
        }
        return identityKey;
    }

    protected X509Certificate getIdentityCert()
    throws Exception {
        if (identityCert == null) {
            readIdentity();
        }

        return identityCert;
    }

    private void readIdentity()
    throws Exception {
        char[] pwd = readPasswordIfNotSet(password);

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(p12File), pwd);

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
            throw new Exception("no key entry is contained in the keystore");
        }

        this.identityKey = (PrivateKey) ks.getKey(keyname, pwd);
        this.identityCert = (X509Certificate) ks.getCertificate(keyname);
    }

    protected X509Certificate extractEECerts(
            final CertStore certstore)
    throws CertStoreException {
        Iterator<?> it = certstore.getCertificates(null).iterator();
        while (it.hasNext()) {
            X509Certificate m = (X509Certificate) it.next();
            if (-1 == m.getBasicConstraints()) {
                return m;
            }
        }
        return null;
    }

}
