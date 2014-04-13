package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.stream.XMLStreamException;

import org.xipki.database.api.DataSource;
import org.xipki.dbi.ca.jaxb.CAConfigurationType;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasCertprofiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasPublishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasRequestors;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Caaliases;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Cas;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Certprofiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Cmpcontrols;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Crlsigners;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Environments;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Publishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Requestors;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Responders;
import org.xipki.dbi.ca.jaxb.CaHasCertprofileType;
import org.xipki.dbi.ca.jaxb.CaHasPublisherType;
import org.xipki.dbi.ca.jaxb.CaHasRequestorType;
import org.xipki.dbi.ca.jaxb.CaType;
import org.xipki.dbi.ca.jaxb.CaaliasType;
import org.xipki.dbi.ca.jaxb.CertprofileType;
import org.xipki.dbi.ca.jaxb.CmpcontrolType;
import org.xipki.dbi.ca.jaxb.CrlsignerType;
import org.xipki.dbi.ca.jaxb.EnvironmentType;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.dbi.ca.jaxb.PublisherType;
import org.xipki.dbi.ca.jaxb.RequestorType;
import org.xipki.dbi.ca.jaxb.ResponderType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.ParamChecker;

class CaConfigurationDbExporter extends DbPorter{
	private final Marshaller marshaller;
	
	CaConfigurationDbExporter(DataSource dataSource, Marshaller marshaller, String destDir) 
			throws SQLException, PasswordResolverException, IOException
	{
		super(dataSource, destDir);
		ParamChecker.assertNotNull("marshaller", marshaller);
		this.marshaller = marshaller;
	}

	public void export() throws Exception
	{	
		CAConfigurationType caconf = new CAConfigurationType();
		caconf.setVersion(VERSION);
		
		caconf.setCmpcontrols(export_cmpcontrol());
		
		caconf.setResponders(export_responder());

		caconf.setEnvironments(export_environment());
		
		caconf.setCrlsigners(export_crlsigner());
		
		caconf.setRequestors(export_requestor());
		
		caconf.setPublishers(export_publisher());
		
		caconf.setCertprofiles(export_certprofile());
		
		caconf.setCas(export_ca());
		
		caconf.setCaaliases(export_caalias());
		
		caconf.setCaHasRequestors(export_ca_has_requestor());
		
		caconf.setCaHasPublishers(export_ca_has_publisher());
		
		caconf.setCaHasCertprofiles(export_ca_has_certprofile());
		
		JAXBElement<CAConfigurationType> root = new ObjectFactory().createCAConfiguration(caconf);
		marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_CA_Configuration));
	}

	private Cmpcontrols export_cmpcontrol()
	throws SQLException
	{
		Cmpcontrols cmpcontrols = new Cmpcontrols();
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, require_confirm_cert, send_ca_cert, "
					+ " message_time_bias, confirm_wait_time"
					+ " FROM cmpcontrol";
			ResultSet rs = stmt.executeQuery(sql);		

			while(rs.next()){
				String name = rs.getString("name");
				boolean requireConfirmCert = rs.getBoolean("require_confirm_cert");
				boolean sendCaCert = rs.getBoolean("send_ca_cert");
				int messageTimeBias = rs.getInt("message_time_bias");
				int confirmWaitTime = rs.getInt("confirm_wait_time");

				CmpcontrolType cmpcontrol = new CmpcontrolType();
				cmpcontrols.getCmpcontrol().add(cmpcontrol);

				cmpcontrol.setName(name);
				cmpcontrol.setRequireConfirmCert(requireConfirmCert);
				cmpcontrol.setSendCaCert(sendCaCert);
				cmpcontrol.setMessageTimeBias(messageTimeBias);
				cmpcontrol.setConfirmWaitTime(confirmWaitTime);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return cmpcontrols;
	}

	private Environments export_environment()
	throws SQLException
	{
		Environments environments = new Environments();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, value FROM environment";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String value = rs.getString("value");
		
				EnvironmentType environment = new EnvironmentType();
				environment.setName(name);
				environment.setValue(value);
				environments.getEnvironment().add(environment);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return environments;
	}

	private Crlsigners export_crlsigner()
	throws XMLStreamException, SQLException
	{
		Crlsigners crlsigners = new Crlsigners(); 
				
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, signer_type, signer_conf, signer_cert, period,"
					+ " overlap, include_certs_in_crl"
					+ " FROM crlsigner";
			ResultSet rs = stmt.executeQuery(sql);		

			while(rs.next()){
				String name = rs.getString("name");
				String signer_type = rs.getString("signer_type");
				String signer_conf = rs.getString("signer_conf");
				String signer_cert = rs.getString("signer_cert");
				int period = rs.getInt("period");
				int overlap = rs.getInt("overlap");
				boolean include_certs_in_crl = rs.getBoolean("include_certs_in_crl");

				CrlsignerType crlsigner = new CrlsignerType();
				crlsigner.setName(name);
				crlsigner.setSignerType(signer_type);
				crlsigner.setSignerConf(signer_conf);
				crlsigner.setSignerCert(signer_cert);
				crlsigner.setPeriod(period);
				crlsigner.setOverlap(overlap);
				crlsigner.setIncludeCertsInCrl(include_certs_in_crl);
				
				crlsigners.getCrlsigner().add(crlsigner);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return crlsigners;
	}

	private Caaliases export_caalias()
	throws XMLStreamException, SQLException
	{
		Caaliases caaliases = new Caaliases();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, ca_name FROM caalias";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String caName = rs.getString("ca_name");

				CaaliasType caalias = new CaaliasType();
				caalias.setName(name);
				caalias.setCaName(caName);
				
				caaliases.getCaalias().add(caalias);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return caaliases;
	}
	
	private Requestors export_requestor()
	throws XMLStreamException, SQLException
	{
		Requestors requestors = new Requestors();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, cert FROM requestor";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String cert = rs.getString("cert");
				
				RequestorType requestor = new RequestorType();
				requestor.setName(name);
				requestor.setCert(cert);
				
				requestors.getRequestor().add(requestor);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return requestors;
	}

	private Responders export_responder()
	throws XMLStreamException, SQLException
	{
		Responders responders = new Responders();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, type, cert, conf FROM responder";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String type = rs.getString("type");
				String conf = rs.getString("conf");
				String cert = rs.getString("cert");
		
				ResponderType responder = new ResponderType();
				responder.setName(name);
				responder.setType(type);
				responder.setConf(conf);
				responder.setCert(cert);
				
				responders.getResponder().add(responder);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return responders;
	}

	private Publishers export_publisher()
	throws XMLStreamException, SQLException
	{
		Publishers publishers = new Publishers();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, type, conf FROM publisher";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String type = rs.getString("type");
				String conf = rs.getString("conf");
				
				PublisherType publisher = new PublisherType();
				publisher.setName(name);
				publisher.setType(type);
				publisher.setConf(conf);
				
				publishers.getPublisher().add(publisher);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return publishers;
	}

	private Certprofiles export_certprofile()
	throws XMLStreamException, SQLException
	{
		Certprofiles certprofiles = new Certprofiles();

		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, type, conf FROM certprofile";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String type = rs.getString("type");
				String conf = rs.getString("conf");

				CertprofileType certprofile = new CertprofileType();
				certprofile.setName(name);
				certprofile.setType(type);
				certprofile.setConf(conf);
				
				certprofiles.getCertprofile().add(certprofile);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return certprofiles;
	}

	private Cas export_ca()
	throws XMLStreamException, SQLException
	{
		Cas cas = new Cas();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			
			String sqlPart1 = "SELECT name, subject, next_serial, status, crl_uris, ocsp_uris, max_validity, "
					+ "cert, signer_type, signer_conf, crlsigner_name, "
					+ "allow_duplicate_key, allow_duplicate_subject, permissions";
			String sqlPart2 = " FROM ca";

			ResultSet rs;
			boolean sqlWith_num_crls = true;
			try{
				String sql = sqlPart1 + ", num_crls" + sqlPart2;
				rs = stmt.executeQuery(sql);
			}catch(SQLException e)
			{
				sqlWith_num_crls = false;
				String sql = sqlPart1 + sqlPart2;
				rs = stmt.executeQuery(sql);
			}
	
			while(rs.next())
			{
				String name = rs.getString("name");
				String subject = rs.getString("subject");
				String next_serial = rs.getString("next_serial");
				String status = rs.getString("status");
				String crl_uris = rs.getString("crl_uris");
				String ocsp_uris = rs.getString("ocsp_uris");			
				int max_validity = rs.getInt("max_validity");
				String cert = rs.getString("cert");
				String signer_type = rs.getString("signer_type");
				String signer_conf = rs.getString("signer_conf");
				String crlsigner_name = rs.getString("crlsigner_name");
				boolean allowDuplicateKey = rs.getBoolean("allow_duplicate_key");
				boolean allowDuplicateSubject = rs.getBoolean("allow_duplicate_subject");
				Integer numCrls = null;
				if(sqlWith_num_crls)
				{
					numCrls = rs.getInt("num_crls");
				}
				
				String permissions = rs.getString("permissions");
				
				CaType ca = new CaType();
				ca.setName(name);
				ca.setSubject(subject);
				ca.setNextSerial(next_serial);
				ca.setStatus(status);
				ca.setCrlUris(crl_uris);
				ca.setOcspUris(ocsp_uris);
				ca.setMaxValidity(max_validity);
				ca.setCert(cert);
				ca.setSignerType(signer_type);
				ca.setSignerConf(signer_conf);
				ca.setCrlsignerName(crlsigner_name);
				ca.setAllowDuplicateKey(allowDuplicateKey);
				ca.setAllowDuplicateSubject(allowDuplicateSubject);
				ca.setPermissions(permissions);
				ca.setNumCrls(numCrls);
				
				cas.getCa().add(ca);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return cas;
	}

	private CaHasRequestors export_ca_has_requestor()
	throws XMLStreamException, SQLException
	{
		CaHasRequestors ca_has_requestors = new CaHasRequestors();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			
			String sql = "SELECT ca_name, requestor_name, ra, permissions, profiles FROM ca_has_requestor";
			ResultSet rs = stmt.executeQuery(sql);
			
			while(rs.next()){
				String ca_name = rs.getString("ca_name");
				String requestor_name = rs.getString("requestor_name");
				boolean ra = rs.getBoolean("ra");
				String permissions = rs.getString("permissions");
				String profiles = rs.getString("profiles");			

				CaHasRequestorType ca_has_requestor = new CaHasRequestorType();
				ca_has_requestor.setCaName(ca_name);
				ca_has_requestor.setRequestorName(requestor_name);
				ca_has_requestor.setRa(ra);
				ca_has_requestor.setPermissionts(permissions);
				ca_has_requestor.setProfiles(profiles);
				
				ca_has_requestors.getCaHasRequestor().add(ca_has_requestor);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return ca_has_requestors;
	}

	private CaHasPublishers export_ca_has_publisher()
	throws XMLStreamException, SQLException
	{
		CaHasPublishers ca_has_publishers = new CaHasPublishers();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			
			String sql = "SELECT ca_name, publisher_name FROM ca_has_publisher";
			ResultSet rs = stmt.executeQuery(sql);
			
			while(rs.next()){
				String ca_name = rs.getString("ca_name");
				String publisher_name = rs.getString("publisher_name");
				
				CaHasPublisherType ca_has_publisher = new CaHasPublisherType();
				ca_has_publisher.setCaName(ca_name);
				ca_has_publisher.setPublisherName(publisher_name);;
				
				ca_has_publishers.getCaHasPublisher().add(ca_has_publisher);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return ca_has_publishers;
	}


	private CaHasCertprofiles export_ca_has_certprofile()
	throws XMLStreamException, SQLException
	{
		CaHasCertprofiles ca_has_certprofiles = new CaHasCertprofiles();

		Statement stmt = null;
		try{
			stmt = createStatement();
			
			String sql = "SELECT ca_name, certprofile_name FROM ca_has_certprofile";
			ResultSet rs = stmt.executeQuery(sql);
			
			while(rs.next()){
				String ca_name = rs.getString("ca_name");
				String certprofile_name = rs.getString("certprofile_name");
		
				CaHasCertprofileType ca_has_certprofile = new CaHasCertprofileType();
				ca_has_certprofile.setCaName(ca_name);
				ca_has_certprofile.setCertprofileName(certprofile_name);
				
				ca_has_certprofiles.getCaHasCertprofile().add(ca_has_certprofile);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return ca_has_certprofiles;
	}
	
}