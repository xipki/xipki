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

package org.xipki.security;

import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

/**
 *
 * @author Lijun Liao
 *
 */
public class Testor
{

    public static void main(String[] args)
    {
        try
        {
            f2();
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void f2()
    throws Exception
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("cert_profile?C.SAK.AUT%");
        System.out.println(pairs.getEncoded());
        final String fn = "/home/lliao/Downloads/ad/T_systems.pki";
        PKIMessage pki = PKIMessage.getInstance(IoCertUtil.read(fn));
        CertReqMessages msgs = (CertReqMessages) pki.getBody().getContent();
        int i = 0;
        for(CertReqMsg msg : msgs.toCertReqMsgArray())
        {
            System.out.println("BEGIN " + i);
            SubjectPublicKeyInfo pkInfo = msg.getCertReq().getCertTemplate().getPublicKey();
            byte[] encodedPKInfo = pkInfo.getPublicKeyData().getBytes();
            IoCertUtil.save(new File("/home/lliao/Downloads/ad/pkInfo.der"), encodedPKInfo);

            SubjectPublicKeyInfo pkInfo2 = SubjectPublicKeyInfo.getInstance(encodedPKInfo);
            PublicKey pk = KeyUtil.generatePublicKey(pkInfo2);
            System.out.println("  END " + i);
            i++;
        }
    }

    private static void f1()
    {
        final String fn =  "/home/lliao/Downloads/ad/a.hex";
        final String fn2 =  "/home/lliao/Downloads/ad/a";
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            String s = new String(IoCertUtil.read(fn));
            s = s.replaceAll(" ", "");
            s = s.replaceAll("-", "");
            byte[] bytes = Hex.decode(s);
            IoCertUtil.save(new File(fn2), bytes);

            SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(bytes);
            RSAPublicKey pk = (RSAPublicKey) KeyUtil.generatePublicKey(pki);
            System.out.println("n: " + pk.getModulus().toString(16));
            System.out.println("e: " + pk.getPublicExponent().toString(16));
            System.out.println("nl: " + pk.getModulus().bitLength());
            System.out.println("el: " + pk.getPublicExponent().bitLength());
            System.out.println(bytes.length);
        }catch(Exception e)
        {
            e.printStackTrace();
        }

    }

}
