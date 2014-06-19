/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.IaikP11ModulePool;
import org.xipki.security.p11.iaik.IaikP11Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "update-cert", description="Update certificate in PKCS#11 device")
public class P11CertUpdateCommand extends SecurityCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 token.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String            keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 token.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String            keyLabel;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String            certFile;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected String            password;

    @Option(name = "-cacert",
            required = false, multiValued = true, description = "CA Certificate files")
    protected Set<String>       caCertFiles;

    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean            readFromConsole;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Pkcs11KeyIdentifier keyIdentifier;
        if(keyId != null && keyLabel == null)
        {
            keyIdentifier = new Pkcs11KeyIdentifier(Hex.decode(keyId));
        }
        else if(keyId == null && keyLabel != null)
        {
            keyIdentifier = new Pkcs11KeyIdentifier(keyLabel);
        }
        else
        {
            throw new Exception("Exactly one of keyId or keyLabel should be specified");
        }

        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        char[] pwd = readPasswordIfNotSet(password, readFromConsole);
        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null), pwd);
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

        byte[] keyId = privKey.getId().getByteArrayValue();
        X509PublicKeyCertificate[] existingCerts = slot.getCertificateObjects(keyId, null);
        X509Certificate newCert = IoCertUtil.parseCert(certFile);

        String pwdStr = pwd == null ? null : new String(pwd);
        assertMatch(newCert, pwdStr);

        Set<X509Certificate> caCerts = new HashSet<>();
        if(caCertFiles != null && caCertFiles.isEmpty() == false)
        {
            for(String caCertFile : caCertFiles)
            {
                caCerts.add(IoCertUtil.parseCert(caCertFile));
            }
        }
        X509Certificate[] certChain = IoCertUtil.buildCertPath(newCert, caCerts);

        Session session = slot.borrowWritableSession();
        try
        {
            X509PublicKeyCertificate newCertTemp = createPkcs11Template(newCert, null, keyId,
                    privKey.getLabel().getCharArrayValue());
            // delete existing signer certificate objects
            if(existingCerts != null && existingCerts.length > 0)
            {
                for(X509PublicKeyCertificate existingCert : existingCerts)
                {
                    session.destroyObject(existingCert);
                }
                Thread.sleep(1000);
            }

            // create new signer certificate object
            session.createObject(newCertTemp);

            // craete CA certificate objects
            if(certChain.length > 1)
            {
                for(int i = 1; i < certChain.length; i++)
                {
                    X509Certificate caCert = certChain[i];
                    byte[] encodedCaCert = caCert.getEncoded();

                    boolean alreadyExists = false;
                    X509PublicKeyCertificate[] certObjs = slot.getCertificateObjects(caCert.getSubjectX500Principal());
                    if(certObjs != null)
                    {
                        for(X509PublicKeyCertificate certObj : certObjs)
                        {
                            if(Arrays.equals(encodedCaCert, certObj.getValue().getByteArrayValue()))
                            {
                                alreadyExists = true;
                                break;
                            }
                        }
                    }

                    if(alreadyExists)
                    {
                        continue;
                    }

                    byte[] caCertKeyId = IaikP11Util.generateKeyID(session);
                    X509PublicKeyCertificate newCaCertTemp = createPkcs11Template(
                            caCert, encodedCaCert, caCertKeyId, null);
                    session.createObject(newCaCertTemp);
                }
            }
        }finally
        {
            slot.returnWritableSession(session);
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd, null, null).refresh();
        System.out.println("Updated certificate");
        return null;
    }

    private void assertMatch(X509Certificate cert, String password)
    throws SignerException, PasswordResolverException
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("slot", slotIndex.toString());
        if(password != null)
        {
            pairs.putUtf8Pair("password", new String(password));
        }
        if(keyId != null)
        {
            pairs.putUtf8Pair("key-id", keyId);
        }
        if(keyLabel != null)
        {
            pairs.putUtf8Pair("key-label", keyLabel);
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

        securityFactory.createSigner("PKCS11", pairs.getEncoded(), cert, NopPasswordResolver.INSTANCE);
    }

    static X509PublicKeyCertificate createPkcs11Template(
            X509Certificate cert, byte[] encodedCert,
            byte[] keyId, char[] label)
    throws Exception
    {
        if(encodedCert == null)
        {
            encodedCert = cert.getEncoded();
        }

        if(label == null)
        {
            X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
            label = IoCertUtil.getCommonName(x500Name).toCharArray();
        }

        X509PublicKeyCertificate newCertTemp = new X509PublicKeyCertificate();
        newCertTemp.getId().setByteArrayValue(keyId);
        newCertTemp.getLabel().setCharArrayValue(label);
        newCertTemp.getToken().setBooleanValue(true);
        newCertTemp.getCertificateType().setLongValue(
                CertificateType.X_509_PUBLIC_KEY);

        newCertTemp.getSubject().setByteArrayValue(
                cert.getSubjectX500Principal().getEncoded());
        newCertTemp.getIssuer().setByteArrayValue(
                cert.getIssuerX500Principal().getEncoded());
        newCertTemp.getSerialNumber().setByteArrayValue(
                cert.getSerialNumber().toByteArray());
        newCertTemp.getValue().setByteArrayValue(encodedCert);
        return newCertTemp;
    }
}
