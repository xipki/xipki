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

package org.xipki.pki.ca.dbtool;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.jaxb.ca.FileOrValueType;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class DbPorter
{
    public static final String FILENAME_CA_Configuration = "ca-configuration.xml";
    public static final String FILENAME_CA_CertStore = "ca-certstore.xml";
    public static final String FILENAME_OCSP_CertStore = "ocsp-certstore.xml";
    public static final String DIRNAME_CRL = "crl";
    public static final String DIRNAME_CERT = "cert";
    public static final String PREFIX_FILENAME_CERTS = "certs-";

    public static final String EXPORT_PROCESS_LOG_FILENAME = "export.process";
    public static final String IMPORT_PROCESS_LOG_FILENAME = "import.process";
    public static final String MSG_CERTS_FINISHED = "certs.finished";
    public static final String IMPORT_TO_OCSP_PROCESS_LOG_FILENAME = "import-to-ocsp.process";

    private static final String CERTS_DIRNAME = "certs";
    private static final String CERTS_MANIFEST_FILENAME = "certs-manifest";

    public static final int VERSION = 1;

    protected final AtomicBoolean stopMe;
    protected final DataSourceWrapper dataSource;
    private Connection connection;
    private boolean connectionAutoCommit;
    protected final boolean evaulateOnly;

    protected final String baseDir;
    protected final String certsDir;
    protected final String certsListFile;

    protected final int dbSchemaVersion;
    protected final int maxX500nameLen;

    public DbPorter(
            final DataSourceWrapper dataSource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws DataAccessException
    {
        super();
        ParamUtil.assertNotNull("dataSource", dataSource);
        ParamUtil.assertNotBlank("baseDir", baseDir);
        ParamUtil.assertNotNull("stopMe", stopMe);

        this.stopMe = stopMe;
        this.dataSource = dataSource;
        this.evaulateOnly = evaluateOnly;
        this.connection = this.dataSource.getConnection();
        try
        {
            this.connectionAutoCommit = connection.getAutoCommit();
        } catch (SQLException e)
        {
            throw dataSource.translate(null, e);
        }
        this.baseDir = IoUtil.expandFilepath(baseDir);
        this.certsDir = this.baseDir + File.separator + CERTS_DIRNAME;
        this.certsListFile = this.baseDir + File.separator + CERTS_MANIFEST_FILENAME;

        DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(dataSource);
        String s = dbSchemaInfo.getVariableValue("VERSION");
        this.dbSchemaVersion = Integer.parseInt(s);
        s = dbSchemaInfo.getVariableValue("X500NAME_MAXLEN");
        this.maxX500nameLen = Integer.parseInt(s);
    }

    protected static void setLong(
            final PreparedStatement ps,
            final int index,
            final Long i)
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

    protected static void setInt(
            final PreparedStatement ps,
            final int index,
            final Integer i)
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

    protected static void setBoolean(
            final PreparedStatement ps,
            final int index,
            final boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

    protected Statement createStatement()
    throws DataAccessException
    {
        try
        {
            return connection.createStatement();
        }catch(SQLException e)
        {
            throw dataSource.translate(null, e);
        }
    }

    protected PreparedStatement prepareStatement(
            final String sql)
    throws DataAccessException
    {
        try
        {
            return connection.prepareStatement(sql);
        }catch(SQLException e)
        {
            throw dataSource.translate(sql, e);
        }
    }

    protected void releaseResources(
            final Statement ps,
            final ResultSet rs)
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

    public boolean deleteFromTableWithLargerId(String tableName, String idColumn, int id, Logger log)
    {
        StringBuilder sb = new StringBuilder(50);
        sb.append("DELETE FROM ").append(tableName).append(" WHERE ").append(idColumn).append(" > ").append(id);

        Statement stmt;
        try
        {
            stmt = createStatement();
        } catch (DataAccessException e)
        {
            log.error("could not create statement", e);
            return false;
        }
        try
        {
            stmt.execute(sb.toString());
        } catch(Throwable t)
        {
            log.error("could not delete columns from table " + tableName + " with " + idColumn + " > " + id, t);
            return false;
        }
        finally
        {
            releaseResources(stmt, null);
        }

        return true;
    }

    public void shutdown()
    {
        dataSource.returnConnection(connection);
        connection = null;
    }

    public long getMin(
            final String table,
            final String column)
    throws DataAccessException
    {
        return dataSource.getMin(connection, table, column);
    }

    public long getMax(
            final String table,
            final String column)
    throws DataAccessException
    {
        return dataSource.getMax(connection, table, column);
    }

    public int getCount(
            final String table)
    throws DataAccessException
    {
        return dataSource.getCount(connection, table);
    }

    public boolean tableHasColumn(
            final String table,
            final String column)
    throws DataAccessException
    {
        return dataSource.tableHasColumn(connection, table, column);
    }

    public boolean tableExists(
            final String table)
    throws DataAccessException
    {
        return dataSource.tableExists(connection, table);
    }

    public static final Schema retrieveSchema(
            final String schemaPath)
    throws JAXBException
    {
        URL schemaUrl = DbPorter.class.getResource(schemaPath);
        final SchemaFactory schemaFact = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try
        {
            return schemaFact.newSchema(schemaUrl);
        } catch (SAXException e)
        {
            throw new JAXBException("error while loading schemas for the specified classes\nDetails:\n" + e.getMessage());
        }
    }

    protected Savepoint setSavepoint()
    throws DataAccessException
    {
        try
        {
            return connection.setSavepoint();
        }catch(SQLException e)
        {
            throw dataSource.translate(null, e);
        }
    }

    protected void rollback()
    throws DataAccessException
    {
        try
        {
            connection.rollback();
        }catch(SQLException e)
        {
            throw dataSource.translate(null, e);
        }
    }

    protected DataAccessException translate(
            final String sql,
            final SQLException e)
    {
        return dataSource.translate(sql, e);
    }

    protected void disableAutoCommit()
    throws DataAccessException
    {
        try
        {
            connection.setAutoCommit(false);
        }catch(SQLException e)
        {
            throw dataSource.translate(null, e);
        }
    }

    protected void recoverAutoCommit()
    throws DataAccessException
    {
        try
        {
            connection.setAutoCommit(connectionAutoCommit);
        }catch(SQLException e)
        {
            throw dataSource.translate(null, e);
        }
    }

    protected void commit(
            final String task)
    throws DataAccessException
    {
        try
        {
            connection.commit();
        }catch(SQLException e)
        {
            throw dataSource.translate(task, e);
        }
    }

    public static Properties getDbConfProperties(
            final InputStream is)
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

    public static void echoToFile(
            final String content,
            final File file)
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

    public static void deleteTmpFiles(
            final String dirName,
            final String prefix)
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

    protected static void writeLine(
            final OutputStream os,
            final String text)
    throws IOException
    {
        os.write(text.getBytes());
        os.write('\n');
    }

    protected FileOrValueType buildFileOrValue(
            final String content,
            final String fileName)
    throws IOException
    {
        if(content == null)
        {
            return null;
        }

        FileOrValueType ret = new FileOrValueType();
        if(content.length() < 256)
        {
            ret.setValue(content);
            return ret;
        }

        File file = new File(baseDir, fileName);
        File parent = file.getParentFile();
        if(parent != null && parent.exists() == false)
        {
            parent.mkdirs();
        }

        IoUtil.save(file, content.getBytes("UTF-8"));

        ret.setFile(fileName);
        return ret;
    }

    protected String getValue(
            final FileOrValueType fileOrValue)
    throws IOException
    {
        if(fileOrValue == null)
        {
            return null;
        }

        if(fileOrValue.getValue() != null)
        {
            return fileOrValue.getValue();
        }

        File file = new File(baseDir, fileOrValue.getFile());
        return new String(IoUtil.read(file), "UTF-8");
    }

    protected String getImportingText()
    {
        return evaulateOnly ? "evaluating import " : "importing ";
    }

    protected String getImportedText()
    {
        return evaulateOnly ? " evaluated import " : " imported ";
    }

    protected String getExportingText()
    {
        return evaulateOnly ? "evaluating export " : "exporting ";
    }

    protected String getExportedText()
    {
        return evaulateOnly ? " evaluated export " : " exported ";
    }

    public static String buildFilename(
            final String prefix,
            final String suffix,
            final int minCertIdOfCurrentFile,
            final int maxCertIdOfCurrentFile,
            final int maxCertId)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = Integer.toString(maxCertId).length();
        String a = Integer.toString(minCertIdOfCurrentFile);
        for(int i = 0; i < len - a.length(); i++)
        {
            sb.append('0');
        }
        sb.append(a);
        sb.append("-");

        String b = Integer.toString(maxCertIdOfCurrentFile);
        for(int i = 0; i < len - b.length(); i++)
        {
            sb.append('0');
        }
        sb.append(b);

        sb.append(suffix);
        return sb.toString();
    }
}
