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

import java.io.File;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.console.karaf.FilePathCompleter;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 */

public abstract class P11KeyGenCommand extends KeyGenCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-key-label",
            required = true, description = "Required. Label of the PKCS#11 objects")
    protected String label;

    @Option(name = "-subject",
            required = false, description = "Subject in the self-signed certificate")
    protected String subject;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    @Completion(FilePathCompleter.class)
    protected String outputFilename;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    protected String getSubject()
    {
        if(subject == null || subject.isEmpty())
        {
            return "CN=" + label;
        }
        return subject;
    }

    protected P11SlotIdentifier getSlotId()
    {
        return new P11SlotIdentifier(slotIndex, null);
    }

    protected void saveKeyAndCert(P11KeypairGenerationResult keyAndCert)
    throws Exception
    {
        out("key id: " + Hex.toHexString(keyAndCert.getId()));
        out("key label: " + keyAndCert.getLabel());
        if(outputFilename != null)
        {
            File certFile = new File(outputFilename);
            saveVerbose("Saved self-signed certificate to file", certFile, keyAndCert.getCertificate().getEncoded());
        }

        securityFactory.getP11CryptService(moduleName).refresh();
    }
}
