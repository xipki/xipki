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

package org.xipki.pki.ca.dbtool.diffdb;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class FileDigestReader implements DigestReader
{
    private final int totalAccount;
    private final String caDirname;
    private final String caSubjectName;
    private final X509Certificate caCert;
    private final BufferedReader certsFilesReader;
    private BufferedReader certsReader;
    private DbDigestEntry next;

    public FileDigestReader(
            final String caDirname)
    throws IOException, CertificateException
    {
        ParamUtil.assertNotBlank("caDirname", caDirname);
        this.caDirname = caDirname;

        this.caCert = X509Util.parseCert(
                new File(caDirname, "ca.der"));
        String s = new String(IoUtil.read(new File(caDirname, "account")));
        this.totalAccount = Integer.parseInt(s);
        this.certsFilesReader = new BufferedReader(
                new FileReader(
                        new File(caDirname, "certs-manifest")));
        this.caSubjectName = X509Util.getRFC4519Name(this.caCert.getSubjectX500Principal());
        this.next = retrieveNext(true);
    }

    @Override
    public X509Certificate getCaCert()
    {
        return caCert;
    }

    @Override
    public String getCaSubjectName()
    {
        return this.caSubjectName;
    }

    @Override
    public int getTotalAccount()
    {
        return totalAccount;
    }

    @Override
    public boolean hasNext()
    {
        return next != null;
    }

    @Override
    public DbDigestEntry nextCert()
    {
        if(next == null)
        {
            throw new IllegalStateException("reach end of the stream");
        }

        DbDigestEntry ret = next;
        next = null;
        try
        {
            next = retrieveNext(false);
        } catch (IOException e)
        {
            throw new IllegalStateException("error while retrieving next certificate");
        }
        return ret;
    }

    private DbDigestEntry retrieveNext(
            final boolean firstTime)
    throws IOException
    {
        String line = firstTime
                ? null
                : certsReader.readLine();
        if(line == null)
        {
            close(certsReader);
            String nextFileName = certsFilesReader.readLine();
            if(nextFileName == null)
            {
                return null;
            }
            String filePath = "certs" + File.separator + nextFileName;
            certsReader = new BufferedReader(
                    new FileReader(new File(caDirname, filePath)));
            line = certsReader.readLine();
        }

        return (line == null)
                ? null
                : DbDigestEntry.decode(line);
    }

    @Override
    public void close()
    {
        close(certsFilesReader);
        close(certsReader);
    }

    private static void close(
            final Reader reader)
    {
        if(reader == null)
        {
            return;
        }

        try
        {
            reader.close();
        } catch(Exception e)
        {
        }
    }

}
