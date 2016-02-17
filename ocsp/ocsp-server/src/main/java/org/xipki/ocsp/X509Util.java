/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ocsp;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;

/**
 * @author Lijun Liao
 */

class X509Util
{

    /**
     * Cross certificate will not be considered
     */
    public static X509Certificate[] buildCertPath(
            final X509Certificate cert,
            final Set<? extends Certificate> certs)
            {
        List<X509Certificate> certChain = new LinkedList<>();
        certChain.add(cert);
        try
        {
            if (certs != null && !isSelfSigned(cert))
            {
                while (true)
                {
                    X509Certificate caCert = getCaCertOf(certChain.get(certChain.size() - 1),
                            certs);
                    if (caCert == null)
                    {
                        break;
                    }
                    certChain.add(caCert);
                    if (isSelfSigned(caCert))
                    {
                        // reaches root self-signed certificate
                        break;
                    }
                }
            }
        } catch (CertificateEncodingException e)
        {
        }

        final int n = certChain.size();
        int len = n;
        if (n > 1)
        {
            for (int i = 1; i < n; i++)
            {
                int pathLen = certChain.get(i).getBasicConstraints();
                if (pathLen < 0 || pathLen < i)
                {
                    len = i;
                    break;
                }
            }
        } // end for

        if (len == n)
        {
            return certChain.toArray(new X509Certificate[0]);
        } else
        {
            X509Certificate[] ret = new X509Certificate[len];
            for (int i = 0; i < len; i++)
            {
                ret[i] = certChain.get(i);
            }
            return ret;
        }
    } // method buildCertPath

    public static X509Certificate getCaCertOf(
            final X509Certificate cert,
            final Set<? extends Certificate> caCerts)
    throws CertificateEncodingException
    {
        if (isSelfSigned(cert))
        {
            return null;
        }

        for (Certificate caCert : caCerts)
        {
            if (!(caCert instanceof X509Certificate))
            {
                continue;
            }

            X509Certificate x509CaCert = (X509Certificate) caCert;
            if (!issues(x509CaCert, cert))
            {
                continue;
            }

            try
            {
                cert.verify(x509CaCert.getPublicKey());
                return x509CaCert;
            } catch (Exception e)
            {
            }
        }

        return null;
    }

    public static boolean issues(
            final X509Certificate issuerCert,
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        boolean isCA = issuerCert.getBasicConstraints() >= 0;
        if (!isCA)
        {
            return false;
        }

        boolean issues = issuerCert.getSubjectX500Principal().equals(
                cert.getIssuerX500Principal());
        if (issues)
        {
            byte[] ski = X509Util.extractSki(issuerCert);
            byte[] aki = X509Util.extractAki(cert);
            if (ski != null)
            {
                issues = Arrays.equals(ski, aki);
            }
        }

        if (issues)
        {
            long issuerNotBefore = issuerCert.getNotBefore().getTime();
            long issuerNotAfter = issuerCert.getNotAfter().getTime();
            long notBefore = cert.getNotBefore().getTime();
            issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
        }

        return issues;
    }

    public static boolean isSelfSigned(
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (equals)
        {
            byte[] ski = X509Util.extractSki(cert);
            byte[] aki = X509Util.extractAki(cert);
            if (ski != null && aki != null)
            {
                equals = Arrays.equals(ski, aki);
            }
        }
        return equals;
    }

    public static byte[] extractSki(
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] extValue = getCoreExtValue(cert, Extension.subjectKeyIdentifier);
        if (extValue == null)
        {
            return null;
        }

        try
        {
            return ASN1OctetString.getInstance(extValue).getOctets();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException(e.getMessage());
        }
    }

    public static byte[] extractAki(
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] extValue = getCoreExtValue(cert, Extension.authorityKeyIdentifier);
        if (extValue == null)
        {
            return null;
        }

        try
        {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
            return aki.getKeyIdentifier();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException("invalid extension AuthorityKeyIdentifier: "
                    + e.getMessage());
        }
    }

    private static byte[] getCoreExtValue(
            final X509Certificate cert,
            final ASN1ObjectIdentifier type)
    throws CertificateEncodingException
    {
        byte[] fullExtValue = cert.getExtensionValue(type.getId());
        if (fullExtValue == null)
        {
            return null;
        }
        try
        {
            return ASN1OctetString.getInstance(fullExtValue).getOctets();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException("invalid extension " + type.getId() + ": "
                    + e.getMessage());
        }
    }

}
