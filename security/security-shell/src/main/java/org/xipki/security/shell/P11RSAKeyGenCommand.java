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

import java.math.BigInteger;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa", description="Generate RSA keypair in PKCS#11 device")
@Service
public class P11RSAKeyGenCommand extends P11KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit",
            required = false)
    protected Integer keysize = 2048;

    @Option(name = "-e",
            description = "public exponent",
            required = false)
    protected String publicExponent = "65537";

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(keysize % 1024 != 0)
        {
            throw new IllegalCmdParamException("Keysize is not multiple of 1024: " + keysize);
        }

        BigInteger _publicExponent = new BigInteger(publicExponent);

        P11KeypairGenerator gen = new P11KeypairGenerator(securityFactory);

        P11KeypairGenerationResult keyAndCert = gen.generateRSAKeypairAndCert(
                moduleName, getSlotId(),
                keysize, _publicExponent,
                label, getSubject(),
                getKeyUsage(),
                getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
