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

package org.xipki.security.shell.p12;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.SecurityUtil;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.P10RequestGenerator;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-tk", name = "req-p12", description="Generate PKCS#10 request with PKCS#12 keystore")
public class P12CertRequestGenCommand extends P12SecurityCommand
{
    @Option(name = "-subject",
            required = false,
            description = "Subject in the PKCS#10 request.\n"
                    + "The default is the subject of self-signed certifite.")
    protected String subject;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name.")
    protected String hashAlgo = "SHA256";

    @Option(name = "-out",
            required = true, description = "Required. Output file name")
    protected String outputFilename;

    @Option(name = "-san", aliases="--subjectAltName",
            required = false, multiValued = true, description = "SubjectAltName. Multi-valued.")
    protected List<String> subjectAltNames;

    @Option(name = "-sia", aliases="--subjectInfoAccess",
            required = false, multiValued = true, description = "SubjectInfoAccess. Multi-valued")
    protected List<String> subjectInfoAccesses;

    @Option(name = "-ne", aliases="--needExtension",
            required = false, multiValued = true,
            description = "Types of extension (except SubjectAltName and SubjectInfoAccess) that must\n"
                    + "be contaied in the certificate. Multi-valued")
    protected List<String> needExtensionTypes;

    @Option(name = "-we", aliases="--wantExtension",
            required = false, multiValued = true,
            description = "Types of extension that should be contaied in the certificate if possible.\n"
                    + "Multi-valued")
    protected List<String> wantExtensionTypes;

    @Override
    protected Object doExecute()
    throws Exception
    {
        P10RequestGenerator p10Gen = new P10RequestGenerator();

        char[] pwd = getPassword();

        String signerConf = SecurityFactoryImpl.getKeystoreSignerConfWithoutAlgo(
                p12File, new String(pwd), 1);
        ConcurrentContentSigner identifiedSigner = securityFactory.createSigner(
                "PKCS12", signerConf, hashAlgo, false, (X509Certificate[]) null);

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

        if(needExtensionTypes.isEmpty() == false ||
                (wantExtensionTypes != null && wantExtensionTypes.isEmpty() == false))
        {
            ExtensionExistence ee = new ExtensionExistence(SecurityUtil.textToASN1ObjectIdentifers(needExtensionTypes),
                    SecurityUtil.textToASN1ObjectIdentifers(wantExtensionTypes));
            extensions.add(new Extension(
                    CustomObjectIdentifiers.id_request_extensions, false, ee.toASN1Primitive().getEncoded()));
        }

        Certificate cert = Certificate.getInstance(identifiedSigner.getCertificate().getEncoded());

        X500Name subjectDN;
        if(subject != null)
        {
            subjectDN = new X500Name(subject);
        }
        else
        {
            subjectDN = cert.getSubject();
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();

        ContentSigner signer = identifiedSigner.borrowContentSigner();

        PKCS10CertificationRequest p10Req;
        try
        {
            p10Req  = p10Gen.generateRequest(signer, subjectPublicKeyInfo, subjectDN, extensions);
        }finally
        {
            identifiedSigner.returnContentSigner(signer);
        }

        File file = new File(outputFilename);
        saveVerbose("Saved PKCS#10 request to file", file, p10Req.getEncoded());

        return null;
    }

}
