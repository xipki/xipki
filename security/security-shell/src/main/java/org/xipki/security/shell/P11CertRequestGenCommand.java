/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.p10.Pkcs10RequestGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "req", description="Generate PKCS#10 request with PKCS#11 device")
public class P11CertRequestGenCommand extends P11SecurityCommand
{
    @Option(name = "-subject",
            required = false,
            description = "Subject in the PKCS#10 request.\n"
                    + "The default is the subject of self-signed certifite")
    protected String subject;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name")
    protected String hashAlgo = "SHA256";

    @Option(name = "-out",
            required = true, description = "Required. Output file name")
    protected String outputFilename;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Pkcs10RequestGenerator p10Gen = new Pkcs10RequestGenerator();

        hashAlgo = hashAlgo.trim().toUpperCase();
        if(hashAlgo.indexOf('-') != -1)
        {
            hashAlgo = hashAlgo.replaceAll("-", "");
        }

        P11SlotIdentifier slotIdentifier = new P11SlotIdentifier(slotIndex, null);
        P11KeyIdentifier keyIdentifier = getKeyIdentifier();

        String signerConfWithoutAlgo = SecurityFactoryImpl.getPkcs11SignerConfWithoutAlgo(
                        moduleName, slotIdentifier, keyIdentifier, 1);

        ConcurrentContentSigner identifiedSigner = securityFactory.createSigner("PKCS11",
                signerConfWithoutAlgo, hashAlgo, false,
                (X509Certificate[]) null);

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
            p10Req  = p10Gen.generateRequest(signer, subjectPublicKeyInfo, subjectDN);
        }finally
        {
            identifiedSigner.returnContentSigner(signer);
        }

        File file = new File(outputFilename);
        saveVerbose("Saved PKCS#10 request to file", file, p10Req.getEncoded());
        return null;
    }

}
