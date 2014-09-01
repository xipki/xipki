/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.p10.Pkcs10RequestGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "req-p12", description="Generate PKCS#10 request with PKCS#12 keystore")
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

    private static enum KeyType
    {
        RSA,
        DSA,
        EC,
        OTHER
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        Pkcs10RequestGenerator p10Gen = new Pkcs10RequestGenerator();
        ASN1ObjectIdentifier sigAlgOid;
        KeyStore keystore = getKeyStore();
        char[] pwd = getPassword();
        KeyType keyType = getKeyType(keystore, pwd);

        hashAlgo = hashAlgo.trim().toUpperCase();
        if(hashAlgo.indexOf('-') != -1)
        {
            hashAlgo = hashAlgo.replaceAll("-", "");
        }

        if(keyType == KeyType.RSA)
        {
            if("SHA1".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
            }
            else if("SHA224".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = PKCSObjectIdentifiers.sha224WithRSAEncryption;
            }
            else if("SHA256".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
            }
            else if("SHA384".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
            }
            else if("SHA512".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
            }
            else
            {
                throw new Exception("Unsupported hash algorithm " + hashAlgo);
            }
        }
        else if(keyType == KeyType.DSA)
        {
            if("SHA1".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.id_dsa_with_sha1;
            }
            else if("SHA224".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = NISTObjectIdentifiers.dsa_with_sha224;
            }
            else if("SHA256".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = NISTObjectIdentifiers.dsa_with_sha256;
            }
            else if("SHA384".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = NISTObjectIdentifiers.dsa_with_sha384;
            }
            else if("SHA512".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = NISTObjectIdentifiers.dsa_with_sha512;
            }
            else
            {
                throw new Exception("Unsupported hash algorithm " + hashAlgo);
            }
        }
        else if(keyType == KeyType.EC)
        {
            if("SHA1".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }
            else if("SHA224".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            }
            else if("SHA256".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            }
            else if("SHA384".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            }
            else if("SHA512".equalsIgnoreCase(hashAlgo))
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            }
            else
            {
                throw new Exception("Unsupported hash algorithm " + hashAlgo);
            }
        }
        else
        {
            throw new Exception("Unsupported key type ");
        }

        String signerConf = SecurityFactoryImpl.getKeystoreSignerConf(p12File, new String(pwd), sigAlgOid.getId(), 1);
        ConcurrentContentSigner identifiedSigner = securityFactory.createSigner("PKCS12", signerConf,
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

    private static KeyType getKeyType(KeyStore keystore, char[] password)
    throws Exception
    {
        String keyname = null;
        Enumeration<String> aliases = keystore.aliases();
        while(aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if(keystore.isKeyEntry(alias))
            {
                keyname = alias;
                break;
            }
        }

        if(keyname == null)
        {
            throw new SignerException("Could not find private key");
        }

        PublicKey pub = keystore.getCertificate(keyname).getPublicKey();
        if(pub instanceof ECPublicKey)
        {
            return KeyType.EC;
        }
        else if(pub instanceof RSAPublicKey)
        {
            return KeyType.RSA;
        }
        else if(pub instanceof DSAPublicKey)
        {
            return KeyType.DSA;
        }
        else
        {
            return KeyType.OTHER;
        }
    }

}
