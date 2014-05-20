/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.security.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;

public class IoCertUtil
{
    private static final ASN1ObjectIdentifier[] forwardDNs = new ASN1ObjectIdentifier[]
    {
        ObjectIdentifiers.DN_C,
        ObjectIdentifiers.DN_DC,
        ObjectIdentifiers.DN_ST,
        ObjectIdentifiers.DN_L,
        ObjectIdentifiers.DN_O,
        ObjectIdentifiers.DN_OU,
        ObjectIdentifiers.DN_T,
        ObjectIdentifiers.DN_SURNAME,
        ObjectIdentifiers.DN_INITIALS,
        ObjectIdentifiers.DN_GIVENNAME,
        ObjectIdentifiers.DN_SERIALNUMBER,
        ObjectIdentifiers.DN_NAME,
        ObjectIdentifiers.DN_CN,
        ObjectIdentifiers.DN_UID,
        ObjectIdentifiers.DN_DMD_NAME,
        ObjectIdentifiers.DN_EmailAddress,
        ObjectIdentifiers.DN_UnstructuredName,
        ObjectIdentifiers.DN_UnstructuredAddress,
        ObjectIdentifiers.DN_POSTAL_CODE,
        ObjectIdentifiers.DN_BUSINESS_CATEGORY,
        ObjectIdentifiers.DN_POSTAL_ADDRESS,
        ObjectIdentifiers.DN_TELEPHONE_NUMBER,
        ObjectIdentifiers.DN_PSEUDONYM,
        ObjectIdentifiers.DN_STREET
    };

    public static String getCommonName(X500Name name)
    {
        RDN[] rdns = name.getRDNs(ObjectIdentifiers.DN_CN);
        if(rdns != null && rdns.length > 0)
        {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    public static X500Name sortX509Name(X500Name name)
    {
        RDN[] requstedRDNs = name.getRDNs();

        List<RDN> rdns = new LinkedList<RDN>();

        for(ASN1ObjectIdentifier type : forwardDNs)
        {
            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = thisRDNs == null ? 0 : thisRDNs.length;
            if(n == 0)
            {
                continue;
            }

            for(RDN thisRDN : thisRDNs)
            {
                String text = IETFUtils.valueToString(thisRDN.getFirst().getValue());
                rdns.add(createSubjectRDN(text, type));
            }
        }

        return new X500Name(rdns.toArray(new RDN[0]));
    }

    private static RDN[] getRDNs(RDN[] rdns, ASN1ObjectIdentifier type)
    {
        List<RDN> ret = new ArrayList<RDN>(1);
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            if(rdn.getFirst().getType().equals(type))
            {
                ret.add(rdn);
            }
        }

        if(ret.isEmpty())
        {
            return null;
        }
        else
        {
            return ret.toArray(new RDN[0]);
        }
    }

    private static RDN createSubjectRDN(String text, ASN1ObjectIdentifier type)
    {
        ASN1Encodable dnValue;
        if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type) ||
           ObjectIdentifiers.DN_C.equals(type))
        {
            dnValue = new DERPrintableString(text);
        }
        else
        {
            dnValue = new DERUTF8String(text);
        }

        RDN rdn = new RDN(type, dnValue);

        return rdn;
    }

    public static byte[] read(String fileName)
    throws IOException
    {
        return read(new File(fileName));
    }

    public static byte[] read(File file)
    throws IOException
    {
        FileInputStream in = null;

        try
        {
            in = new FileInputStream(file);
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally
        {
            if (in != null)
            {
                try
                {
                    in.close();
                } catch (IOException e)
                {
                }
            }
        }
    }

    public static void save(File file, byte[] encoded)
    throws IOException
    {
        File parent = file.getParentFile();
        if (parent != null && parent.exists() == false)
        {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try
        {
            out.write(encoded);
        } finally
        {
            out.close();
        }
    }

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    public static X509Certificate parseCert(String f)
    throws IOException, CertificateException
    {
        return parseCert(new FileInputStream(f));

    }

    public static X509Certificate parseCert(byte[] certBytes)
    throws IOException, CertificateException
    {
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate parseCert(InputStream certStream)
    throws IOException, CertificateException
    {
        synchronized (certFactLock)
        {
            if (certFact == null)
            {
                try
                {
                    certFact = CertificateFactory.getInstance("X.509", "BC");
                } catch (NoSuchProviderException e)
                {
                    throw new IOException("NoSuchProviderException: " + e.getMessage());
                }
            }
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    public static X509CRL parseCRL(String f)
    throws IOException, CertificateException, CRLException
    {
        return parseCRL(new FileInputStream(f));
    }

    public static X509CRL parseCRL(InputStream crlStream)
    throws IOException, CertificateException, CRLException
    {
        try
        {
            if(certFact == null)
            {
                certFact = CertificateFactory.getInstance("X.509", "BC");
            }
            return (X509CRL) certFact.generateCRL(crlStream);
        } catch (NoSuchProviderException e)
        {
            throw new IOException("NoSuchProviderException: " + e.getMessage());
        }
    }

    public static String canonicalizeName(X500Name name)
    {
        try
        {
            X500Principal prin = new X500Principal(name.getEncoded());
            return prin.getName();
        } catch (Exception e)
        {
            throw new IllegalArgumentException("invalid name " + name);
        }
    }

    /**
     * First canonicalized the name, and then compute the SHA-1 finger-print over the
     * canonicalized subject string.
     */
    public static String sha1sum_canonicalized_name(X500Principal prin)
    {
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return sha1sum_canonicalized_name(x500Name);
    }

    public static String sha1sum_canonicalized_name(X500Name name)
    {
        ASN1ObjectIdentifier[] _types = name.getAttributeTypes();
        int n = _types.length;
        List<String> types = new ArrayList<String>(n);
        for(ASN1ObjectIdentifier type : _types)
        {
            types.add(type.getId());
        }

        Collections.sort(types);

        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++)
        {
            String type = types.get(i);
            if(i > 0)
            {
                sb.append(",");
            }
            sb.append(type).append("=");
            RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier(type));

            for(int j = 0; j < rdns.length; j++)
            {
                if(j > 0)
                {
                    sb.append(";");
                }
                RDN rdn = rdns[j];
                String textValue = IETFUtils.valueToString(rdn.getFirst().getValue()).toLowerCase();
                sb.append(textValue);
            }
        }

        String canonicalizedName = sb.toString();
        byte[] encoded;
        try
        {
            encoded = canonicalizedName.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            encoded = canonicalizedName.getBytes();
        }
        return sha1sum(encoded);
    }

    public static String sha1sum(byte[] data)
    {
        return HashCalculator.hexHash(HashAlgoType.SHA1, data);
    }
}
