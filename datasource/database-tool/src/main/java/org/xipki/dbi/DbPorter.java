/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.Properties;

import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class DbPorter
{
    public static final String FILENAME_CA_Configuration = "CA-Configuration.xml";
    public static final String FILENAME_CA_CertStore = "CA-CertStore.xml";
    public static final String FILENAME_OCSP_CertStore = "OCSP-CertStore.xml";
    public static final String DIRNAME_CRL = "CRL";
    public static final String DIRNAME_CERT = "CERT";
    public static final String PREFIX_FILENAME_CERTS = "certs-";

    public static final int VERSION = 1;

    private final DataSourceWrapper dataSource;
    private Connection connection;
    private boolean connectionAutoCommit;

    protected final String baseDir;

    public DbPorter(DataSourceWrapper dataSource, String baseDir)
    throws SQLException
    {
        super();
        ParamChecker.assertNotNull("dataSource", dataSource);
        ParamChecker.assertNotEmpty("baseDir", baseDir);

        this.dataSource = dataSource;
        this.connection = this.dataSource.getConnection();
        this.connectionAutoCommit = connection.getAutoCommit();
        this.baseDir = IoCertUtil.expandFilepath(baseDir);
    }

    protected static void setLong(PreparedStatement ps, int index, Long i)
    throws SQLException
    {
        if(i != null)
        {
            ps.setLong(index, i.longValue());
        }
        else
        {
            ps.setNull(index, Types.BIGINT);
        }
    }

    protected static void setInt(PreparedStatement ps, int index, Integer i)
    throws SQLException
    {
        if(i != null)
        {
            ps.setInt(index, i.intValue());
        }
        else
        {
            ps.setNull(index, Types.INTEGER);
        }
    }

    protected static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

    protected Statement createStatement()
    throws SQLException
    {
        return connection.createStatement();
    }

    protected PreparedStatement prepareStatement(String sql)
    throws SQLException
    {
        return connection.prepareStatement(sql);
    }

    protected void releaseResources(Statement ps, ResultSet rs)
    {
        if(ps != null)
        {
            try
            {
                ps.close();
            }catch(SQLException e)
            {
            }
        }

        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(SQLException e)
            {
            }
        }
    }

    public void shutdown()
    {
        dataSource.returnConnection(connection);
        connection = null;
    }

    public int getMin(String table, String column)
    throws SQLException
    {
        return dataSource.getMin(connection, table, column);
    }

    public int getMax(String table, String column)
    throws SQLException
    {
        return dataSource.getMax(connection, table, column);
    }

    public int getCount(String table)
    throws SQLException
    {
        return dataSource.getCount(connection, table);
    }

    public boolean tableHasColumn(String table, String column)
    throws SQLException
    {
        return dataSource.tableHasColumn(connection, table, column);
    }

    public boolean tableExists(String table)
    throws SQLException
    {
        return dataSource.tableExists(connection, table);
    }

    public static final Schema retrieveSchema(String schemaPath)
    throws JAXBException
    {
        URL schemaUrl = DbPorter.class.getResource(schemaPath);
        final SchemaFactory schemaFact = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try
        {
            return schemaFact.newSchema(schemaUrl);
        } catch (SAXException e)
        {
            throw new JAXBException("Error while loading schemas for the specified classes\nDetails:\n" + e.getMessage());
        }
    }

    protected Savepoint setSavepoint()
    throws SQLException
    {
        return connection.setSavepoint();
    }

    protected void rollback()
    throws SQLException
    {
        connection.rollback();
    }

    protected void disableAutoCommit()
    throws SQLException
    {
        connection.setAutoCommit(false);
    }

    protected void recoverAutoCommit()
    throws SQLException
    {
        connection.setAutoCommit(connectionAutoCommit);
    }

    protected void commit()
    throws SQLException
    {
        connection.commit();
    }

    public static Properties getDbConfProperties(InputStream is)
    throws IOException
    {
        Properties props = new Properties();
        try
        {
            props.load(is);
        }finally
        {
            try
            {
                is.close();
            }catch(IOException e)
            {
            }
        }

        // adapt the configuration
        if(props.getProperty("minimumIdle") != null)
        {
            props.setProperty("minimumIdle", "1");
        }

        if(props.getProperty("db.minIdle") != null)
        {
            props.setProperty("db.minIdle", "1");
        }

        return props;
    }

    public static void printHeader()
    {
        System.out.println("-----------------------------------------");
        System.out.println(" processed   percent      time       #/s");
    }

    public static void printTrailer()
    {
        System.out.println("\n-----------------------------------------");
    }

    public static void printStatus(long total, long currentAccount, long startTime)
    {
        long now = System.currentTimeMillis();
        String accountS = Long.toString(currentAccount);
        StringBuilder sb = new StringBuilder("\r");

        // 10 characters for processed account
        for (int i = 0; i < 10 -accountS.length(); i++)
        {
            sb.append(" ");
        }
        sb.append(currentAccount);

        // 10 characters for processed percent
        String percent = Long.toString(currentAccount * 100 / total);
        for (int i = 0; i < 9 -percent.length(); i++)
        {
            sb.append(" ");
        }
        sb.append(percent).append('%');

        long t = (now - startTime)/1000;  // in s
        String time = AbstractLoadTest.formatTime(t);
        sb.append("  ");
        sb.append(time);

        String averageS = (t > 0) ? Long.toString(currentAccount / t) : "";
        for (int i = 0; i < 10 -averageS.length(); i++)
        {
            sb.append(" ");
        }
        sb.append(averageS);

        System.out.print(sb.toString());
        System.out.flush();
    }

    public static void echoToFile(String content, File file)
    throws IOException
    {
        FileOutputStream out = null;
        try
        {
            out = new FileOutputStream(file);
            out.write(content.getBytes());
        } finally
        {
            if(out != null)
            {
                out.flush();
                out.close();
            }
        }
    }

    public static void deleteTmpFiles(String dirName, String prefix)
    {
        // delete the temporary files
        File dir = new File(dirName);
        File[] children = dir.listFiles();
        if(children != null && children.length > 0)
        {
            for(File child : children)
            {
                if(child.getName().startsWith(prefix))
                {
                    child.delete();
                }
            }
        }
    }

}
