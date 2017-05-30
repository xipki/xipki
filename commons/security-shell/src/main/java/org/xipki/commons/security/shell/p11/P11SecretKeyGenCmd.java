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

package org.xipki.commons.security.shell.p11;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.security.pkcs11.P11ObjectIdentifier;
import org.xipki.commons.security.pkcs11.P11Slot;
import org.xipki.commons.security.shell.completer.SecretKeyTypeCompleter;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xipki-tk", name = "secretkey",
        description = "generate secret key in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11SecretKeyGenCmd extends P11KeyGenCommandSupport {

    @Option(name = "--key-type",
            required = true,
            description = "keytype, current only AES, DES3 and GENERIC are supported\n"
                    + "(required)")
    @Completion(SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--key-size",
            required = true,
            description = "keysize in bit.")
    private Integer keysize;

    @Override
    protected Object doExecute() throws Exception {
        long p11KeyType;
        if ("AES".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_AES;

        } else if ("DES3".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_DES3;
        } else if ("GENERIC".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_GENERIC_SECRET;
        } else {
            throw new IllegalCmdParamException("invalid keyType " + keyType);
        }

        P11Slot slot = getSlot();
        P11ObjectIdentifier objId = slot.generateSecretKey(p11KeyType, keysize, label,
                getControl());
        finalize("Generate Secret Key", objId);
        return null;
    }

    @Override
    protected boolean getDefaultExtractable() {
        return true;
    }

}
