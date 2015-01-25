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

package org.xipki.dbtool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.AbstractLoadTest;
import org.xipki.common.IoUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class CaDbImporter
{
    private static class CAInfoBundle
    {
        private final String CA_name;
        private final long CA_nextSerial;
        private final byte[] cert;

        private long should_CA_nextSerial;
        private Integer CAINFO_id;

        public CAInfoBundle(String CA_name, long CA_nextSerial, byte[] cert)
        {
            this.CA_name = CA_name;
            this.CA_nextSerial = CA_nextSerial;
            this.should_CA_nextSerial = CA_nextSerial;
            this.cert = cert;
        }

    }

    private static final Logger LOG = LoggerFactory.getLogger(CaDbImporter.class);
    private final DataSourceWrapper dataSource;
    private final Unmarshaller unmarshaller;
    protected final boolean resume;

    public CaDbImporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, boolean resume)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.dataSource = dataSourceFactory.createDataSource(null, props, passwordResolver);
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
        this.resume = resume;
    }

    public void importDatabase(String srcFolder)
    throws Exception
    {
        File processLogFile = new File(srcFolder, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        if(resume)
        {
            if(processLogFile.exists() == false)
            {
                throw new Exception("Could not process with '-resume' option");
            }
        }
        else
        {
            if(processLogFile.exists())
            {
                throw new Exception("Please either specify '-resume' option or delete the file " +
                        processLogFile.getPath() + " first");
            }
        }

        long start = System.currentTimeMillis();
        try
        {
            if(resume == false)
            {
                // CAConfiguration
                CaConfigurationDbImporter caConfImporter = new CaConfigurationDbImporter(
                        dataSource, unmarshaller, srcFolder);
                caConfImporter.importToDB();
                caConfImporter.shutdown();
            }

            // CertStore
            CaCertStoreDbImporter certStoreImporter = new CaCertStoreDbImporter(dataSource, unmarshaller, srcFolder, resume);
            certStoreImporter.importToDB();
            certStoreImporter.shutdown();

            // create serialNumber generator
            createSerialNumberSequences();
        } finally
        {
            try
            {
                dataSource.shutdown();
            }catch(Throwable e)
            {
                LOG.error("dataSource.shutdown()", e);
            }
            long end = System.currentTimeMillis();
            System.out.println("Finished in " + AbstractLoadTest.formatTime((end - start) / 1000).trim());
        }
    }

    private void createSerialNumberSequences()
    throws Exception
    {
        List<CAInfoBundle> CAInfoBundles = new LinkedList<>();

        // create the sequence for the certificate serial numbers
        Connection conn = dataSource.getConnection();
        try
        {
            Statement st = dataSource.createStatement(conn);
            ResultSet rs = st.executeQuery("SELECT NAME, NEXT_SERIAL, CERT FROM CA");

            while(rs.next())
            {
                long nextSerial = rs.getLong("NEXT_SERIAL");
                if(nextSerial < 1)
                {
                    // random serial number assignment
                    continue;
                }

                String CA_name = rs.getString("NAME");
                byte[] cert = Base64.decode(rs.getString("CERT"));
                CAInfoBundle entry = new CAInfoBundle(CA_name, nextSerial, cert);
                CAInfoBundles.add(entry);
            }

            rs.close();

            if(CAInfoBundles.isEmpty())
            {
                return;
            }

            // get the CAINFO.ID
            rs = st.executeQuery("SELECT ID, CERT FROM CAINFO");
            while(rs.next())
            {
                byte[] cert = Base64.decode(rs.getString("CERT"));
                int id = rs.getInt("ID");
                for(CAInfoBundle entry : CAInfoBundles)
                {
                    if(Arrays.equals(cert, entry.cert))
                    {
                        entry.CAINFO_id = id;
                        break;
                    }
                }
            }

            rs.close();
            st.close();

            // get the maximal serial number
            PreparedStatement ps = conn.prepareStatement("SELECT MAX(SERIAL) FROM CERT WHERE CAINFO_ID=?");
            for(CAInfoBundle entry : CAInfoBundles)
            {
                ps.setInt(1, entry.CAINFO_id);
                rs = ps.executeQuery();
                if(rs.next() == false)
                {
                    continue;
                }

                long maxSerial = rs.getLong(1);
                if(maxSerial + 1 > entry.CA_nextSerial)
                {
                    entry.should_CA_nextSerial = maxSerial + 1;
                }
                rs.close();
            }
            ps.close();

            ps = conn.prepareStatement("UPDATE CA SET NEXT_SERIAL=? WHERE NAME=?");
            for(CAInfoBundle entry : CAInfoBundles)
            {
                if(entry.CA_nextSerial != entry.should_CA_nextSerial)
                {
                    ps.setLong(1, entry.should_CA_nextSerial);
                    ps.setString(2, entry.CA_name);
                    ps.executeUpdate();
                }
            }

        }finally
        {
            dataSource.returnConnection(conn);
        }

        // create the sequences
        for(CAInfoBundle entry : CAInfoBundles)
        {
            long nextSerial = Math.max(entry.CA_nextSerial, entry.should_CA_nextSerial);
            String seqName = IoUtil.convertSequenceName("SERIAL_" + entry.CA_name);
            dataSource.dropAndCreateSequence(seqName, nextSerial);
        }

    }

}
