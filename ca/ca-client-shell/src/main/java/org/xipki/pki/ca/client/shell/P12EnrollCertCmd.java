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

package org.xipki.pki.ca.client.shell;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.SecurityFactoryImpl;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.commons.security.api.SignerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-cli", name = "enroll-p12",
        description = "enroll certificate (PKCS#12 keystore)")
@Service
public class P12EnrollCertCmd extends EnrollCertCommandSupport {

    @Option(name = "--p12",
            required = true,
            description = "PKCS#12 request file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(name = "--password",
            description = "password of the PKCS#12 file")
    private String password;

    @Override
    protected ConcurrentContentSigner getSigner(
            final String hashAlgo,
            final SignatureAlgoControl signatureAlgoControl)
    throws SignerException {
        if (password == null) {
            password = new String(readPassword());
        }

        String signerConfWithoutAlgo = SecurityFactoryImpl.getKeystoreSignerConfWithoutAlgo(
                p12File, password, 1);
        return securityFactory.createSigner("PKCS12", signerConfWithoutAlgo, hashAlgo,
                signatureAlgoControl, (X509Certificate[]) null);
    }

}
