/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;

import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xipki.database.api.DataSourceWrapper;
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

    protected final String baseDir;

    public DbPorter(DataSourceWrapper dataSource, String baseDir)
    throws SQLException
    {
        super();
        ParamChecker.assertNotNull("dataSource", dataSource);
        ParamChecker.assertNotEmpty("baseDir", baseDir);

        this.dataSource = dataSource;
        this.connection = this.dataSource.getConnection();
        this.baseDir = baseDir;
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

}
