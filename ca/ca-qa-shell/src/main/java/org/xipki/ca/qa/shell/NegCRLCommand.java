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

package org.xipki.ca.qa.shell;

import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.client.api.PKIErrorException;
import org.xipki.ca.client.api.RAWorkerException;
import org.xipki.ca.client.shell.ClientCommand;
import org.xipki.console.karaf.UnexpectedResultException;

/**
 * @author Lijun Liao
 */

public abstract class NegCRLCommand extends ClientCommand
{

    @Option(name = "-ca",
            required = false, description = "Required if multiple CAs are configured. CA name")
    protected String caName;

    protected abstract X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            err("No CA is configured");
            return  null;
        }

        if(caName != null && ! caNames.contains(caName))
        {
            err("CA " + caName + " is not within the configured CAs " + caNames);
            return null;
        }

        if(caName == null)
        {
            if(caNames.size() == 1)
            {
                caName = caNames.iterator().next();
            }
            else
            {
                err("No caname is specified, one of " + caNames + " is required");
                return null;
            }
        }

        X509CRL crl = null;
        try
        {
            crl = retrieveCRL(caName);
        }catch(PKIErrorException e)
        {
        }

        if(crl != null)
        {
            throw new UnexpectedResultException("No CRL is expected, but received one");
        }

        return null;
    }

}
