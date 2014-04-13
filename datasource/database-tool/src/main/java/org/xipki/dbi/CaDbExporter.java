package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

public class CaDbExporter {	
	
	private final DataSource dataSource;
	private final Marshaller marshaller;
	
	public CaDbExporter(DataSourceFactory dataSourceFactory,
			PasswordResolver passwordResolver, String dbConfFile) 
			throws SQLException, PasswordResolverException, IOException, JAXBException 
	{
		this.dataSource = dataSourceFactory.createDataSourceForFile(dbConfFile, passwordResolver);
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
	}

	public void exportDatabase(String destFolder)
	throws Exception
	{
		File f = new File(destFolder);
		if(f.exists() == false)
		{
			f.mkdirs();
		}
		else
		{
			if(f.isDirectory() == false)
			{
				throw new IOException(destFolder + " is not a folder");
			}
			
			if(f.canWrite() == false)
			{
				throw new IOException(destFolder + " is not writable");
			}
		}

		String[] children = f.list();
		if(children != null && children.length > 0)
		{
			throw new IOException(destFolder + " is not empty");
		}

		// CAConfiguration
		CaConfigurationDbExporter caConfExporter = new CaConfigurationDbExporter(dataSource, marshaller, destFolder);
		caConfExporter.export();
		
		// CertStore
		CaCertStoreDbExporter certStoreExporter = new CaCertStoreDbExporter(dataSource, marshaller, destFolder);
		certStoreExporter.export();
	}
	
}
