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

package org.xipki.pki.ca.dbtool.report;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;

/**
 * @author Lijun Liao
 */

public class DbReporter extends DbToolBase
{
    public static final String REPORTS_DIRNAME = "report";
    public static final String REPORTS_MANIFEST_FILENAME = "reports-manifest";
    public static final int DFLT_NUM_CERTS_IN_BUNDLE = 100000;

    protected final int numCertsPerSelect;

    public DbReporter(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final int numCertsPerSelect)
    throws DataAccessException, IOException
    {
        super(datasource, baseDir, stopMe);
        if(numCertsPerSelect < 1)
        {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: " + numCertsPerSelect);
        }

        this.numCertsPerSelect = numCertsPerSelect;

        File f = new File(baseDir);
        if(f.exists() == false)
        {
            f.mkdirs();
        }
        else
        {
            if(f.isDirectory() == false)
            {
                throw new IOException(baseDir + " is not a folder");
            }

            if(f.canWrite() == false)
            {
                throw new IOException(baseDir + " is not writable");
            }
        }

        String[] children = f.list();
        if(children != null && children.length > 0)
        {
            throw new IOException(baseDir + " is not empty");
        }
    }

    public static String buildFilename(
            final String prefix,
            final String suffix,
            final int minIdOfCurrentFile)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = 10;
        String a = Integer.toString(minIdOfCurrentFile);
        for(int i = 0; i < len - a.length(); i++)
        {
            sb.append('0');
        }
        sb.append(a);

        sb.append(suffix);
        return sb.toString();
    }

}
