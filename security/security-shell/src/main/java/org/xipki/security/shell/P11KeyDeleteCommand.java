/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "delete-key", description="Generate EC keypair in PKCS#11 device")
@Service
public class P11KeyDeleteCommand extends P11SecurityCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        P11KeyIdentifier keyIdentifier = getKeyIdentifier();
        IaikExtendedModule module = getModule(moduleName);

        IaikExtendedSlot slot = module.getSlot(new P11SlotIdentifier(slotIndex, null));

        char[] keyLabelChars = (keyLabel == null) ?
                null : keyLabel.toCharArray();

        PrivateKey privKey = slot.getPrivateObject(null, null, keyIdentifier.getKeyId(), keyLabelChars);
        if(privKey == null)
        {
            throw new IllegalCmdParamException("Could not find private key " + keyIdentifier);
        }

        Session session = slot.borrowWritableSession();
        try
        {
            try
            {
                session.destroyObject(privKey);
                out("Deleted private key");
            }catch(TokenException e)
            {
                out("Could not delete private key");
                throw e;
            }

            PublicKey pubKey = slot.getPublicKeyObject(null, null,
                    privKey.getId().getByteArrayValue(), null);
            if(pubKey != null)
            {
                try
                {
                    session.destroyObject(pubKey);
                    out("Deleted public key");
                }catch(TokenException e)
                {
                    out("Could not delete public key");
                    throw e;
                }
            }

            X509PublicKeyCertificate[] certs = slot.getCertificateObjects(privKey.getId().getByteArrayValue(), null);
            if(certs != null && certs.length > 0)
            {
                int nDeleted = 0;
                for(int i = 0; i < certs.length; i++)
                {
                    try
                    {
                        session.destroyObject(certs[i]);
                        nDeleted++;
                    }catch(TokenException e)
                    {
                        out("Could not delete certificate at index " + i);
                        throw e;
                    }
                }
                if(nDeleted > 0)
                {
                    StringBuilder sb = new StringBuilder("Deleted ");
                    sb.append(nDeleted);
                    sb.append(nDeleted == 1 ? " certificate" : " certificates");
                    out(sb.toString());
                }
            }

            securityFactory.getP11CryptService(moduleName).refresh();
        }finally
        {
            slot.returnWritableSession(session);
        }

        return null;
    }
}
