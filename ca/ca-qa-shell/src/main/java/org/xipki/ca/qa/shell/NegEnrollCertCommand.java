/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.ca.client.api.CertOrError;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.ca.client.shell.ClientCommand;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.qa.UnexpectedResultException;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public abstract class NegEnrollCertCommand extends ClientCommand
{
    @Option(name = "--subject", aliases = "-s",
            description = "subject to be requested.\n"
                    + "default is the subject of self-signed certifite.")
    private String subject;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "certificate profile\n"
                    + "(required)")
    private String profile;

    @Option(name = "--user",
            description = "username")
    private String user;

    @Option(name = "--hash",
            description = "hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "--ca",
            description = "CA name\n"
                    + "required if the profile is supported by more than one CA")
    private String caName;

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected abstract ConcurrentContentSigner getSigner()
    throws SignerException;

    @Override
    protected Object _doExecute()
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

        EnrollCertResult result;
        RequestResponseDebug debug = getRequestResponseDebug();
        try
        {
            result = raWorker.requestCerts(request, caName, user, debug);
        }finally
        {
            saveRequestResponse(debug);
        }

        X509Certificate cert = null;
        if(result != null)
        {
            String id = result.getAllIds().iterator().next();
            CertOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if(cert != null)
        {
            throw new UnexpectedResultException("no certificate is excepted, but received one");
        }

        return null;
    }

}
