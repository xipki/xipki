package org.xipki.dbi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.database.api.DataSource;
import org.xipki.security.common.ParamChecker;

class DbPorter {
	public static final String FILENAME_CA_Configuration = "CA-Configuration.xml";
	public static final String FILENAME_CA_CertStore = "CA-CertStore.xml";
	public static final String FILENAME_OCSP_CertStore = "OCSP-CertStore.xml";
	public static final String DIRNAME_CRL = "CRL";
	public static final String DIRNAME_CERT = "CERT";
	public static final String PREFIX_FILENAME_CERTS = "certs-";
	
	public static final String VERSION = "1.0";
	
	protected final DataSource dataSource;
	protected final String baseDir;
	protected Connection dsConnection;
	
	DbPorter(DataSource dataSource, String baseDir) 
	{
		super();
		ParamChecker.assertNotNull("dataSource", dataSource);
		ParamChecker.assertNotEmpty("baseDir", baseDir);

		this.dataSource = dataSource;
		this.baseDir = baseDir;
	}
	
	protected Statement createStatement() throws SQLException
	{
			if(dsConnection == null || dsConnection.isClosed())
			{
				dsConnection = dataSource.getConnection(0);
			}
			
			if(dsConnection == null || dsConnection.isClosed())
			{
				throw new SQLException("Could not get connection");
			}
			
			return dsConnection.createStatement();
	}
	
	protected PreparedStatement prepareStatement(String sql) throws SQLException
	{
		if(dsConnection == null || dsConnection.isClosed())
		{
			dsConnection = dataSource.getConnection(0);
		}
		
		if(dsConnection == null || dsConnection.isClosed())
		{
			throw new SQLException("Could not get connection");
		}
		
		return dsConnection.prepareStatement(sql);
	}

	protected static void closeStatement(Statement ps)
	{
		if(ps != null)
		{
			try {
				ps.close();
			} catch (SQLException e) {
			}
		}
	}
}
