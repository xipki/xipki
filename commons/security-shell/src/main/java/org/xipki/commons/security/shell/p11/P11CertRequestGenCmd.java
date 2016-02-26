/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.shell.p11;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.util.SignerConfUtil;
import org.xipki.commons.security.shell.CertRequestGenCommandSupport;
import org.xipki.commons.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "req",
        description = "generate PKCS#10 request with PKCS#11 device")
@Service
public class P11CertRequestGenCmd extends CertRequestGenCommandSupport {

    @Option(name = "--slot",
            required = true,
            description = "slot index\n"
                    + "(required)")
    private Integer slotIndex;

    @Option(name = "--key-id",
            description = "id of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    private String keyId;

    @Option(name = "--key-label",
            description = "label of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    private String keyLabel;

    @Option(name = "--module",
            description = "name of the PKCS#11 module")
    @Completion(P11ModuleNameCompleter.class)
    private String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    private P11KeyIdentifier getKeyIdentifier()
    throws Exception {
        P11KeyIdentifier keyIdentifier;
        if (keyId != null && keyLabel == null) {
            keyIdentifier = new P11KeyIdentifier(Hex.decode(keyId));
        } else if (keyId == null && keyLabel != null) {
            keyIdentifier = new P11KeyIdentifier(keyLabel);
        } else {
            throw new IllegalCmdParamException(
                    "exactly one of keyId or keyLabel should be specified");
        }
        return keyIdentifier;
    }

    @Override
    protected ConcurrentContentSigner getSigner(
            final SignatureAlgoControl signatureAlgoControl)
    throws Exception {
        P11SlotIdentifier slotIdentifier = new P11SlotIdentifier(slotIndex, null);
        P11KeyIdentifier keyIdentifier = getKeyIdentifier();

        String signerConfWithoutAlgo = SignerConfUtil.getPkcs11SignerConfWithoutAlgo(
                        moduleName, slotIdentifier, keyIdentifier, 1);

        return securityFactory.createSigner("PKCS11",
                signerConfWithoutAlgo, hashAlgo, signatureAlgoControl,
                (X509Certificate[]) null);
    }

}
