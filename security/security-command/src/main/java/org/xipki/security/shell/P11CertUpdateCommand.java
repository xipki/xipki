/*
 * Copyright 2014 xipki.org
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

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

@Command(scope = "keytool", name = "update-cert", description="Update certificate in PKCS#11 device")
public class P11CertUpdateCommand extends OsgiCommandSupport
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyLabel;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String            certFile;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected char[]            password;

    private SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Object doExecute() throws Exception
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

        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null), password);
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

        X509PublicKeyCertificate existingCert = slot.getCertificateObject(privKey.getId().getByteArrayValue(), null);
        X509Certificate newCert = IoCertUtil.parseCert(certFile);

        assertMatch(newCert);

        Session session = slot.borrowWritableSession();
        try
        {
            X509PublicKeyCertificate newCertTemp;

            newCertTemp = new X509PublicKeyCertificate();
            newCertTemp.getId().setByteArrayValue(
                    privKey.getId().getByteArrayValue());
            newCertTemp.getLabel().setCharArrayValue(
                    privKey.getLabel().getCharArrayValue());
            newCertTemp.getToken().setBooleanValue(true);
            newCertTemp.getCertificateType().setLongValue(
                    CertificateType.X_509_PUBLIC_KEY);

            newCertTemp.getSubject().setByteArrayValue(
                    newCert.getSubjectX500Principal().getEncoded());
            newCertTemp.getIssuer().setByteArrayValue(
                    newCert.getIssuerX500Principal().getEncoded());
            newCertTemp.getSerialNumber().setByteArrayValue(
                    newCert.getSerialNumber().toByteArray());
            newCertTemp.getValue().setByteArrayValue(
                    newCert.getEncoded());

            if(existingCert != null)
            {
                session.destroyObject(existingCert);
                Thread.sleep(1000);
            }

            session.createObject(newCertTemp);
        }finally
        {
            slot.returnWritableSession(session);
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), password).refresh();
        System.out.println("Updated certificate");
        return null;
    }

    private void assertMatch(X509Certificate cert) throws SignerException, PasswordResolverException
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

}
