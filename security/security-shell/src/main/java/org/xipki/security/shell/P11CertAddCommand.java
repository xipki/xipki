/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.FilePathCompleter;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11Util;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "add-cert", description="Add certificate to PKCS#11 device")
@Service
public class P11CertAddCommand extends SecurityCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    @Completion(FilePathCompleter.class)
    protected String certFile;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    @Override
    protected Object doExecute()
    throws Exception
    {
        IaikExtendedModule module = getModule(moduleName);

        IaikExtendedSlot slot = module.getSlot(new P11SlotIdentifier(slotIndex, null));

        X509Certificate cert = IoCertUtil.parseCert(certFile);

        Session session = slot.borrowWritableSession();
        try
        {
            byte[] encodedCert = cert.getEncoded();

            X509PublicKeyCertificate[] certObjs = slot.getCertificateObjects(cert.getSubjectX500Principal());
            if(certObjs != null)
            {
                for(X509PublicKeyCertificate certObj : certObjs)
                {
                    if(Arrays.equals(encodedCert, certObj.getValue().getByteArrayValue()))
                    {
                        P11KeyIdentifier p11KeyId = new P11KeyIdentifier(
                                certObj.getId().getByteArrayValue(),
                                new String(certObj.getLabel().getCharArrayValue()));
                        throw new CmdFailure(
                                "Given certificate already exists under " + p11KeyId);
                    }
                }
            }

            byte[] keyId = IaikP11Util.generateKeyID(session);
            X509PublicKeyCertificate newCaCertTemp = P11CertUpdateCommand.createPkcs11Template(
                    cert, encodedCert, keyId, null);
            session.createObject(newCaCertTemp);
            P11KeyIdentifier p11KeyId = new P11KeyIdentifier(keyId,
                    new String(newCaCertTemp.getLabel().getCharArrayValue()));
            out("Added certificate under " + p11KeyId);
        }finally
        {
            slot.returnWritableSession(session);
        }

        securityFactory.getP11CryptService(moduleName).refresh();
        return null;
    }

}
