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

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.ca.client.api.CertificateOrError;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.KeyUsage;
import org.xipki.common.SecurityUtil;
import org.xipki.console.karaf.UnexpectedResultException;
import org.xipki.security.P10RequestGenerator;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.ExtensionExistence;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public abstract class EnrollCertCommand extends ClientCommand
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
    protected String outputFile;

    @Option(name = "-user",
            required = false, description = "Username")
    protected String user;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "-ca",
            required = false, description = "Required if the profile is supported by more than one CA")
    protected String caName;

    @Option(name = "-keyusage",
            required = false, multiValued = true, description = "keyusage. Multi-valued.")
    protected List<String> keyusages;

    @Option(name = "-extKeyusage",
            required = false, multiValued = true, description = "extended keyusage. Multi-valued.")
    protected List<String> extkeyusages;

    @Option(name = "-subjectAltName",
            required = false, multiValued = true, description = "SubjectAltName. Multi-valued.")
    protected List<String> subjectAltNames;

    @Option(name = "-subjectInfoAccess",
            required = false, multiValued = true, description = "SubjectInfoAccess. Multi-valued")
    protected List<String> subjectInfoAccesses;

    @Option(name = "-needExtension",
            required = false, multiValued = true,
            description = "Types of extension that must be contaied in the certificate. Multi-valued")
    protected List<String> needExtensionTypes;

    @Option(name = "-wantExtension",
            required = false, multiValued = true,
            description = "Types of extension that should be contaied in the certificate if possible.\n"
                    + "Multi-valued")
    protected List<String> wantExtensionTypes;

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

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

        if(needExtensionTypes == null)
        {
            needExtensionTypes = new LinkedList<>();
        }

        // SubjectAltNames
        List<Extension> extensions = new LinkedList<>();
        if(subjectAltNames != null && subjectAltNames.isEmpty() == false)
        {
            extensions.add(P10RequestGenerator.createExtensionSubjectAltName(subjectAltNames, false));
            needExtensionTypes.add(Extension.subjectAlternativeName.getId());
        }

        // SubjectInfoAccess
        if(subjectInfoAccesses != null && subjectInfoAccesses.isEmpty() == false)
        {
            extensions.add(P10RequestGenerator.createExtensionSubjectInfoAccess(subjectInfoAccesses, false));
            needExtensionTypes.add(Extension.subjectInfoAccess.getId());
        }

        // Keyusage
        if(keyusages != null && keyusages.isEmpty() == false)
        {
            Set<KeyUsage> usages = new HashSet<>();
            for(String usage : keyusages)
            {
                usages.add(KeyUsage.getKeyUsage(usage));
            }
            org.bouncycastle.asn1.x509.KeyUsage extValue = SecurityUtil.createKeyUsage(usages);
            ASN1ObjectIdentifier extType = Extension.keyUsage;
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        }

        // ExtendedKeyusage
        if(extkeyusages != null && extkeyusages.isEmpty() == false)
        {
            Set<ASN1ObjectIdentifier> oids = new HashSet<>(
                    SecurityUtil.textToASN1ObjectIdentifers(extkeyusages));
            ExtendedKeyUsage extValue = SecurityUtil.createExtendedUsage(oids);
            ASN1ObjectIdentifier extType = Extension.extendedKeyUsage;
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        }

        if(needExtensionTypes.isEmpty() == false ||
                (wantExtensionTypes != null && wantExtensionTypes.isEmpty() == false))
        {
            ExtensionExistence ee = new ExtensionExistence(SecurityUtil.textToASN1ObjectIdentifers(needExtensionTypes),
                    SecurityUtil.textToASN1ObjectIdentifers(wantExtensionTypes));
            extensions.add(new Extension(
                    CustomObjectIdentifiers.id_cmp_request_extensions, false, ee.toASN1Primitive().getEncoded()));
        }

        if(extensions != null && extensions.isEmpty() == false)
        {
            Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
            certTemplateBuilder.setExtensions(asn1Extensions);
        }

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

        EnrollCertResult result = raWorker.requestCerts(request, caName, user);

        X509Certificate cert = null;
        if(result != null)
        {
            String id = result.getAllIds().iterator().next();
            CertificateOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if(cert == null)
        {
            throw new UnexpectedResultException("No certificate received from the server");
        }

        File certFile = new File(outputFile);
        saveVerbose("Certificate saved to file", certFile, cert.getEncoded());

        return null;
    }

}
