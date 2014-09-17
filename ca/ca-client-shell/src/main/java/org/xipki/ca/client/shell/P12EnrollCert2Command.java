/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "enroll2-p12", description="Enroll certificate as non-RA (PKCS#12 keystore)")
public class P12EnrollCert2Command extends EnrollCert2Command
{
    @Option(name = "-p12",
            required = true, description = "Required. PKCS#12 request file")
    protected String p12File;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#12 file")
    protected String password;

    private static enum KeyType
    {
        RSA,
        DSA,
        EC,
        OTHER
    }

    @Override
    protected ConcurrentContentSigner getSigner()
    throws SignerException
    {
        /*
        if(password == null)
        {
            password = new String(readPassword());
        }
        KeyStore keystore = getKeyStore(password.toCharArray());
        KeyType keyType = getKeyType(keystore, password.toCharArray());
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

        CmpUtf8Pairs confBuilder = new CmpUtf8Pairs();
        confBuilder.putUtf8Pair("password", password);
*/

        return null;
    }

    protected KeyStore getKeyStore(char[] password)
    throws Exception
    {
        KeyStore ks;

        FileInputStream fIn = null;
        try
        {
            fIn = new FileInputStream(expandFilepath(p12File));
            ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(fIn, password);
        }finally
        {
            if(fIn != null)
            {
                fIn.close();
            }
        }

        return ks;
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
