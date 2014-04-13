package org.xipki.dbi;

import java.io.IOException;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

public class OcspDbImporter {	
	
	private final DataSource dataSource;
	private final Unmarshaller unmarshaller;
	
	public OcspDbImporter(DataSourceFactory dataSourceFactory,
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
		// CertStore
		OcspCertStoreDbImporter certStoreImporter = new OcspCertStoreDbImporter(dataSource, unmarshaller, srcFolder);
		certStoreImporter.importToDB();
	}
	
	
}
