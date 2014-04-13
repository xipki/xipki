package org.xipki.dbi;

import java.io.IOException;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

public class CaDbImporter {	
	
	private final DataSource dataSource;
	private final Unmarshaller unmarshaller;
	
	public CaDbImporter(DataSourceFactory dataSourceFactory,
			PasswordResolver passwordResolver, String dbConfFile) 
			throws SQLException, PasswordResolverException, IOException, JAXBException 
	{
		this.dataSource = dataSourceFactory.createDataSourceForFile(dbConfFile, passwordResolver);
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		unmarshaller = jaxbContext.createUnmarshaller();
	}

	public void importDatabase(String srcFolder)
	throws Exception
	{
		// CAConfiguration
		CaConfigurationDbImporter caConfImporter = new CaConfigurationDbImporter(
				dataSource, unmarshaller, srcFolder);
		caConfImporter.importToDB();
		
		// CertStore
		CaCertStoreDbImporter certStoreImporter = new CaCertStoreDbImporter(dataSource, unmarshaller, srcFolder);
		certStoreImporter.importToDB();
	}
	
	
}
