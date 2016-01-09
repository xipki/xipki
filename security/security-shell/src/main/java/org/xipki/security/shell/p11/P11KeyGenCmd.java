/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.security.shell.p11;

import java.io.File;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.shell.KeyGenCmd;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 */

public abstract class P11KeyGenCmd extends KeyGenCmd {

    @Option(name = "--slot",
            required = true,
            description = "slot index\n"
                    + "(required)")
    protected Integer slotIndex;

    @Option(name = "--key-label",
            required = true,
            description = "label of the PKCS#11 objects\n"
                    + "(required)")
    protected String label;

    @Option(name = "--no-cert",
            required = false,
            description = "Generate only keypair without self-signed certificate")
    protected Boolean noCert = Boolean.FALSE;

    @Option(name = "--subject", aliases = "-s",
            description = "subject in the self-signed certificate")
    protected String subject;

    @Option(name = "--cert-out",
            description = "where to save the self-signed certificate")
    @Completion(FilePathCompleter.class)
    protected String outputFilename;

    @Option(name = "--module",
            description = "Name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    protected String getSubject() {
        if (isBlank(subject)) {
            return "CN=" + label;
        }
        return subject;
    }

    protected P11SlotIdentifier getSlotId() {
        return new P11SlotIdentifier(slotIndex, null);
    }

    protected void finalize(
            final P11KeyIdentifier keyId)
    throws Exception {
        out("generate PKCS#11 key");
        out("\tkey id: " + Hex.toHexString(keyId.getKeyId()));
        out("\tkey label: " + keyId.getKeyLabel());

        securityFactory.getP11CryptService(moduleName).refresh();
    }

    protected void finalize(
            final P11KeypairGenerationResult keyAndCert)
    throws Exception {
        out("generate PKCS#11 key");
        out("\tkey id: " + Hex.toHexString(keyAndCert.getId()));
        out("\tkey label: " + keyAndCert.getLabel());
        if (outputFilename != null) {
            File certFile = new File(outputFilename);
            saveVerbose("\tsaved self-signed certificate to file", certFile,
                    keyAndCert.getCertificate().getEncoded());
        }

        securityFactory.getP11CryptService(moduleName).refresh();
    }
}
