/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.p10.Pkcs10RequestGenerator;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "req", description="Generate PKCS#10 request with PKCS#11 device")
public class P11CertRequestGenCommand extends P11SecurityCommand
{
    @Option(name = "-subject",
            required = false,
            description = "Subject in the PKCS#10 request.\n"
                    + "The default is the subject of self-signed certifite.")
    protected String            subject;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

    @Option(name = "-out",
            required = true, description = "Required. Output file name")
    protected String            outputFilename;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(hashAlgo == null)
        {
            hashAlgo = "SHA256";
        }

        Pkcs11KeyIdentifier keyIdentifier = getKeyIdentifier();
        char[] pwd = getPassword();

        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null),
                    pwd);
        }catch(SignerException e)
        {
            System.err.println("ERROR:  " + e.getMessage());
            return null;
        }

        char[] keyLabelChars = (keyLabel == null) ?
                null : keyLabel.toCharArray();

        PrivateKey privKey = slot.getPrivateObject(null, null, keyIdentifier.getKeyId(), keyLabelChars);
        if(privKey == null)
        {
            System.err.println("Could not find private key " + keyIdentifier);
            return null;
        }

        boolean ec = privKey instanceof ECDSAPrivateKey;

        Pkcs10RequestGenerator p10Gen = new Pkcs10RequestGenerator();

        ASN1ObjectIdentifier sigAlgOid;

        hashAlgo = hashAlgo.trim().toUpperCase();

        if("SHA256".equalsIgnoreCase(hashAlgo) || "SHA-256".equalsIgnoreCase(hashAlgo))
        {
            sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA256 : PKCSObjectIdentifiers.sha256WithRSAEncryption;
        }
        else if("SHA384".equalsIgnoreCase(hashAlgo) || "SHA-384".equalsIgnoreCase(hashAlgo))
        {
            sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA384 : PKCSObjectIdentifiers.sha384WithRSAEncryption;
        }
        else if("SHA512".equalsIgnoreCase(hashAlgo) || "SHA-512".equalsIgnoreCase(hashAlgo))
        {
            sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA512 : PKCSObjectIdentifiers.sha512WithRSAEncryption;
        }
        else
        {
            throw new Exception("Unsupported hash algorithm " + hashAlgo);
        }

        PKCS11SlotIdentifier slotId = new PKCS11SlotIdentifier(slotIndex, null);
        String pwdStr = pwd == null ? null : new String(pwd);
        String signerConf = SecurityFactoryImpl.getPkcs11SignerConf(
                        securityFactory.getPkcs11Module(),
                        slotId, keyIdentifier,
                        pwdStr,
                        sigAlgOid.getId(), 1);

        ConcurrentContentSigner identifiedSigner = securityFactory.createSigner("PKCS11", signerConf,
                (X509Certificate[]) null, NopPasswordResolver.INSTANCE);

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
