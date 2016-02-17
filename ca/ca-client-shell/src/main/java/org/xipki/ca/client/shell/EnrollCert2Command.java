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

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.common.CertificateOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.FilePathCompleter;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public abstract class EnrollCert2Command extends ClientCommand
{
    @Option(name = "-subject",
            required = false,
            description = "Subject to be requested.\n"
                    + "The default is the subject of self-signed certifite.")
    protected String subject;

    @Option(name = "-profile",
            required = true, description = "Required. Certificate profile")
    protected String profile;

    @Option(name = "-out",
            required = true, description = "Where to save the certificate")
    @Completion(FilePathCompleter.class)
    protected String outputFile;

    @Option(name = "-user",
            required = false, description = "Username")
    protected String user;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Reference
    protected SecurityFactory securityFactory;

    protected abstract ConcurrentContentSigner getSigner()
    throws SignerException;

    @Override
    protected Object doExecute()
    throws Exception
    {
        EnrollCertRequestType request = new EnrollCertRequestType(EnrollCertRequestType.Type.CERT_REQ);

        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

        ConcurrentContentSigner signer = getSigner();
        X509CertificateHolder ssCert = signer.getCertificateAsBCObject();

        X500Name x500Subject = subject == null ? ssCert.getSubject() : new X500Name(subject);
        certTemplateBuilder.setSubject(x500Subject);
        certTemplateBuilder.setPublicKey(ssCert.getSubjectPublicKeyInfo());
        CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);

        ProofOfPossessionSigningKeyBuilder popoBuilder = new ProofOfPossessionSigningKeyBuilder(certReq);
        ContentSigner contentSigner = signer.borrowContentSigner();
        POPOSigningKey popoSk;
        try
        {
            popoSk = popoBuilder.build(contentSigner);
        }finally
        {
            signer.returnContentSigner(contentSigner);
        }

        ProofOfPossession popo = new ProofOfPossession(popoSk);

        EnrollCertRequestEntryType reqEntry = new EnrollCertRequestEntryType("id-1", profile, certReq, popo);
        request.addRequestEntry(reqEntry);

        EnrollCertResult result = raWorker.requestCerts(request, null, user);

        X509Certificate cert = null;
        if(result != null)
        {
            String id = result.getAllIds().iterator().next();
            CertificateOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if(cert == null)
        {
            throw new CmdFailure("No certificate received from the server");
        }

        File certFile = new File(outputFile);
        saveVerbose("Certificate saved to file", certFile, cert.getEncoded());

        return null;
    }

}
