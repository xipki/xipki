/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.client.shell;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.ca.client.shell.completer.P11ModuleNameCompleter;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "enroll2", description="Enroll certificate as non-RA (PKCS#11 token)")
@Service
public class P11EnrollCert2Command extends EnrollCert2Command
{
    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String keyLabel;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    @Override
    protected ConcurrentContentSigner getSigner()
    throws SignerException
    {
        P11SlotIdentifier slotIdentifier = new P11SlotIdentifier(slotIndex, null);
        P11KeyIdentifier keyIdentifier = getKeyIdentifier();

        String signerConfWithoutAlgo = SecurityFactoryImpl.getPkcs11SignerConfWithoutAlgo(
                moduleName, slotIdentifier, keyIdentifier, 1);
        return securityFactory.createSigner("PKCS11", signerConfWithoutAlgo, hashAlgo, false, (X509Certificate[]) null);
    }

    private P11KeyIdentifier getKeyIdentifier()
    throws SignerException
    {
        P11KeyIdentifier keyIdentifier;
        if(keyId != null && keyLabel == null)
        {
            keyIdentifier = new P11KeyIdentifier(Hex.decode(keyId));
        }
        else if(keyId == null && keyLabel != null)
        {
            keyIdentifier = new P11KeyIdentifier(keyLabel);
        }
        else
        {
            throw new SignerException("Exactly one of keyId or keyLabel should be specified");
        }
        return keyIdentifier;
    }

}
