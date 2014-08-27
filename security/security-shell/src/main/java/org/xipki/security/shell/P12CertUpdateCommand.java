/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "update-cert-p12", description="Update certificate in PKCS#12 keystore")
public class P12CertUpdateCommand extends P12SecurityCommand
{
    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String certFile;

    @Option(name = "-cacert",
            required = false, multiValued = true, description = "CA Certificate files")
    protected Set<String> caCertFiles;

    @Override
    protected Object doExecute()
    throws Exception
    {
        KeyStore ks = getKeyStore();

        char[] pwd = getPassword();
        X509Certificate newCert = IoCertUtil.parseCert(certFile);

        assertMatch(newCert, new String(pwd));

        String keyname = null;
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if(ks.isKeyEntry(alias))
            {
                keyname = alias;
                break;
            }
        }

        if(keyname == null)
        {
            throw new SignerException("Could not find private key");
        }

        Key key = ks.getKey(keyname, pwd);
        Set<X509Certificate> caCerts = new HashSet<>();
        if(caCertFiles != null && caCertFiles.isEmpty() == false)
        {
            for(String caCertFile : caCertFiles)
            {
                caCerts.add(IoCertUtil.parseCert(caCertFile));
            }
        }
        X509Certificate[] certChain = IoCertUtil.buildCertPath(newCert, caCerts);

        ks.setKeyEntry(keyname, key, pwd, certChain);

        FileOutputStream fOut = null;
        try
        {
            fOut = new FileOutputStream(p12File);
            ks.store(fOut, pwd);
            out("Updated certificate");
            return null;
        }finally
        {
            if(fOut != null)
            {
                fOut.close();
            }
        }
    }

    private void assertMatch(X509Certificate cert, String password)
    throws SignerException, PasswordResolverException
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("keystore", "file:" + p12File);
        if(password != null)
        {
            pairs.putUtf8Pair("password", new String(password));
        }

        PublicKey pubKey = cert.getPublicKey();
        if(pubKey instanceof RSAPublicKey)
        {
            pairs.putUtf8Pair("algo", "SHA1withRSA");
        }
        else if(pubKey instanceof ECPublicKey)
        {
            pairs.putUtf8Pair("algo", "SHA1withECDSA");
        }
        else
        {
            throw new SignerException("Unknown key type: " + pubKey.getClass().getName());
        }

        securityFactory.createSigner("PKCS12", pairs.getEncoded(), cert, NopPasswordResolver.INSTANCE);
    }

}
