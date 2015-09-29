/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.pki.ocsp.server.impl.certstore;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.xipki.security.api.HashCalculator;

/**
 * @author Lijun Liao
 */

public class IssuerFilter
{
    private final Set<String> includeSha1Fps;
    private final Set<String> excludeSha1Fps;

    public IssuerFilter(
            final Set<X509Certificate> includes,
            final Set<X509Certificate> excludes)
    throws CertificateEncodingException
    {
        if (includes == null)
        {
            includeSha1Fps = null;
        } else
        {
            includeSha1Fps = new HashSet<>(includes.size());
            for (X509Certificate include : includes)
            {
                String sha1Fp = HashCalculator.base64Sha1(include.getEncoded());
                includeSha1Fps.add(sha1Fp);
            }
        }

        if (excludes == null)
        {
            excludeSha1Fps = null;
        } else
        {
            excludeSha1Fps = new HashSet<>(excludes.size());
            for (X509Certificate exclude : excludes)
            {
                String sha1Fp = HashCalculator.base64Sha1(exclude.getEncoded());
                excludeSha1Fps.add(sha1Fp);
            }
        }
    }

    public boolean includeIssuerWithSha1Fp(
            final String sha1Fp)
    {
        if (includeSha1Fps == null || includeSha1Fps.contains(sha1Fp))
        {
            if (excludeSha1Fps == null)
            {
                return true;
            } else
            {
                return !excludeSha1Fps.contains(sha1Fp);
            }
        } else
        {
            return false;
        }
    }
}
