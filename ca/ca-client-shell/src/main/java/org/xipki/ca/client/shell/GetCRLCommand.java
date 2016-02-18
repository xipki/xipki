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

package org.xipki.ca.client.shell;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.FilePathCompleter;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "getcrl", description="Download CRL")
@Service
public class GetCRLCommand extends CRLCommand
{
    @Option(name = "-with-basecrl",
            required = false, description = "Indicates whether to retrieve the baseCRL if the current CRL is a delta CRL")
    protected Boolean withBaseCRL = Boolean.FALSE;

    @Option(name = "-basecrl-out",
            required = false, description = "Where to save the baseCRL"
                    + "\nThe default is <out>-baseCRL")
    @Completion(FilePathCompleter.class)
    protected String baseCRLOut;

    @Override
    protected X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return raWorker.downloadCRL(caName);
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            throw new CmdFailure("No CA is configured");
        }

        if(caName != null && ! caNames.contains(caName))
        {
            throw new CmdFailure("CA " + caName + " is not within the configured CAs " + caNames);
        }

        if(caName == null)
        {
            if(caNames.size() == 1)
            {
                caName = caNames.iterator().next();
            }
            else
            {
                throw new CmdFailure("No caname is specified, one of " + caNames + " is required");
            }
        }

        X509CRL crl = retrieveCRL(caName);
        if(crl == null)
        {
            throw new CmdFailure("Received no CRL from server");
        }

        saveVerbose("Saved CRL to file", new File(outFile), crl.getEncoded());

        if(withBaseCRL.booleanValue())
        {
            byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
            if(octetString != null)
            {
                if(baseCRLOut == null)
                {
                    baseCRLOut = outFile + "-baseCRL";
                }

                byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                crl = raWorker.downloadCRL(caName, baseCrlNumber);
                if(crl == null)
                {
                    throw new CmdFailure("Received no baseCRL from server");
                }
                else
                {
                    saveVerbose("Saved baseCRL to file", new File(baseCRLOut), crl.getEncoded());
                }
            }
        }

        return null;
    }
}
