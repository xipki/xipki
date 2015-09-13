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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

public class DbToolBase
{
    private static final int STREAM_BUFFER_SIZE = 1048576; // 1M

    protected final AtomicBoolean stopMe;
    protected final DataSourceWrapper dataSource;
    protected Connection connection;
    private boolean connectionAutoCommit;

    protected final String baseDir;

    public DbToolBase(
            final DataSourceWrapper dataSource,
            final String baseDir,
            final AtomicBoolean stopMe)
    throws DataAccessException
    {
        super();
        ParamUtil.assertNotNull("dataSource", dataSource);
        ParamUtil.assertNotBlank("baseDir", baseDir);
        ParamUtil.assertNotNull("stopMe", stopMe);

        this.stopMe = stopMe;
        this.dataSource = dataSource;
        this.connection = this.dataSource.getConnection();
        try
        {
            this.connectionAutoCommit = connection.getAutoCommit();
        } catch (SQLException e)
        {
            throw dataSource.translate(null, e);
        }
        this.baseDir = IoUtil.expandFilepath(baseDir);
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
        int i =  b
                ? 1
                : 0;
        ps.setInt(index, i);
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

    public boolean deleteFromTableWithLargerId(
            final String tableName,
            final String idColumn,
            final int id,
            final Logger log)
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

    public long getMin(
            final String table,
            final String column,
            final String condition)
    throws DataAccessException
    {
        return dataSource.getMin(connection, table, column, condition);
    }

    public long getMax(
            final String table,
            final String column)
    throws DataAccessException
    {
        return dataSource.getMax(connection, table, column);
    }

    public long getMax(
            final String table,
            final String column,
            final String condition)
    throws DataAccessException
    {
        return dataSource.getMax(connection, table, column, condition);
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

    public static String buildFilename(
            final String prefix,
            final String suffix,
            final int minIdOfCurrentFile,
            final int maxIdOfCurrentFile,
            final int maxId)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = Integer.toString(maxId).length();
        String a = Integer.toString(minIdOfCurrentFile);
        for(int i = 0; i < len - a.length(); i++)
        {
            sb.append('0');
        }
        sb.append(a);
        sb.append("-");

        String b = Integer.toString(maxIdOfCurrentFile);
        for(int i = 0; i < len - b.length(); i++)
        {
            sb.append('0');
        }
        sb.append(b);

        sb.append(suffix);
        return sb.toString();
    }

    public static ZipOutputStream getZipOutputStream(
            final File zipFile)
    throws FileNotFoundException
    {
        BufferedOutputStream out = new BufferedOutputStream(
                new FileOutputStream(zipFile), STREAM_BUFFER_SIZE);
        ZipOutputStream zipOutStream = new ZipOutputStream(out);
        zipOutStream.setLevel(Deflater.BEST_SPEED);
        return zipOutStream;
    }
}
