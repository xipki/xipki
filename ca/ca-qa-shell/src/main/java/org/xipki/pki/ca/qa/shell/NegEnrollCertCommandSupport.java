/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.qa.shell;

import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

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
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.completer.HashAlgCompleter;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.pki.ca.client.api.CertOrError;
import org.xipki.pki.ca.client.api.EnrollCertResult;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.pki.ca.client.shell.ClientCommandSupport;
import org.xipki.pki.ca.client.shell.completer.CaNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class NegEnrollCertCommandSupport extends ClientCommandSupport {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--hash",
            description = "hash algorithm name for the POPO computation")
    @Completion(HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

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

    @Option(name = "--rsa-mgf1",
            description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
                    + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--dsa-plain",
            description = "whether to use the Plain DSA for the POPO computation\n"
                    + "(only applied to DSA and ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--ca",
            description = "CA name\n"
                    + "required if the profile is supported by more than one CA")
    @Completion(CaNameCompleter.class)
    private String caName;

    protected abstract ConcurrentContentSigner getSigner(
            @Nonnull SignatureAlgoControl signatureAlgoControl)
    throws SecurityException;

    @Override
    protected Object doExecute()
    throws Exception {
        EnrollCertRequestType request = new EnrollCertRequestType(
                EnrollCertRequestType.Type.CERT_REQ);

        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        ConcurrentContentSigner signer = getSigner(
                new SignatureAlgoControl(rsaMgf1, dsaPlain));
        X509CertificateHolder ssCert = signer.getCertificateAsBcObject();

        X500Name x500Subject = (subject == null)
                ? ssCert.getSubject()
                : new X500Name(subject);
        certTemplateBuilder.setSubject(x500Subject);
        certTemplateBuilder.setPublicKey(ssCert.getSubjectPublicKeyInfo());
        CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);

        ProofOfPossessionSigningKeyBuilder popoBuilder =
                new ProofOfPossessionSigningKeyBuilder(certReq);
        POPOSigningKey popoSk = signer.build(popoBuilder);
        ProofOfPossession popo = new ProofOfPossession(popoSk);

        EnrollCertRequestEntryType reqEntry = new EnrollCertRequestEntryType("id-1", profile,
                certReq, popo);
        request.addRequestEntry(reqEntry);

        EnrollCertResult result;
        RequestResponseDebug debug = getRequestResponseDebug();
        try {
            result = caClient.requestCerts(request, caName, user, debug);
        } finally {
            saveRequestResponse(debug);
        }

        X509Certificate cert = null;
        if (result != null) {
            String id = result.getAllIds().iterator().next();
            CertOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if (cert != null) {
            throw new CmdFailure("no certificate is excepted, but received one");
        }

        return null;
    } // method getSigner

}
