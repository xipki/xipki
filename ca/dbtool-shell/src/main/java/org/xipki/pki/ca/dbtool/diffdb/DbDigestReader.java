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

import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class DbDigestReader
{
    private final int totalAccount;
    private final String caDirname;
    private final byte[] caCert;
    private final BufferedReader certsFilesReader;
    private BufferedReader certsReader;
    private DbDigestEntry next;

    public DbDigestReader(
            final String caDirname)
    throws IOException
    {
        ParamUtil.assertNotBlank("caDirname", caDirname);
        this.caCert = IoUtil.read(new File(caDirname, "ca.der"));
        String s = new String(IoUtil.read(new File(caDirname, "account")));
        this.totalAccount = Integer.parseInt(s);
        this.certsFilesReader = new BufferedReader(new FileReader(new File(caDirname, "certs-manifest")));
        this.caDirname = caDirname;
        this.next = retrieveNext(true);
    }

    public byte[] getCaCert()
    {
        return caCert;
    }

    public String getCaDirname()
    {
        return caDirname;
    }

    public int getTotalAccount()
    {
        return totalAccount;
    }

    public boolean hasNext()
    {
        return next != null;
    }

    public DbDigestEntry nextCert()
    throws IOException
    {
        if(next == null)
        {
            throw new IllegalStateException("reach end of the stream");
        }

        DbDigestEntry ret = next;
        next = null;
        next = retrieveNext(false);
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
