/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.xipki.dbi.ca.jaxb.PublisherType;
import org.xipki.dbi.ca.jaxb.RequestorType;
import org.xipki.dbi.ca.jaxb.ResponderType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class CaConfigurationDbImporter extends DbPorter{
	private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);
	
	private final Unmarshaller unmarshaller;
	
	CaConfigurationDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir) 
			throws SQLException, PasswordResolverException, IOException
	{
		super(dataSource, srcDir);
		ParamChecker.assertNotNull("unmarshaller", unmarshaller);
		this.unmarshaller = unmarshaller;		
	}

	public void importToDB() throws Exception
	{
		@SuppressWarnings("unchecked")
		JAXBElement<CAConfigurationType> root = (JAXBElement<CAConfigurationType>) 
				unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_CA_Configuration));
		CAConfigurationType caconf = root.getValue();
		
   		import_cmpcontrol(caconf.getCmpcontrols());
   		import_responder(caconf.getResponders());
		import_environment(caconf.getEnvironments());			    	    		
		import_requestor(caconf.getRequestors());			    	    		
		import_publisher(caconf.getPublishers());
		import_certprofile(caconf.getCertprofiles());	
		import_crlsigner(caconf.getCrlsigners());
		import_ca(caconf.getCas());
		import_caalias(caconf.getCaaliases());
		import_ca_has_requestor(caconf.getCaHasRequestors());
		import_ca_has_publisher(caconf.getCaHasPublishers());
		import_ca_has_certprofile(caconf.getCaHasCertprofiles());
	}

	private void import_cmpcontrol(Cmpcontrols controls)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO cmpcontrol (name, require_confirm_cert, send_ca_cert, "
					+ " message_time_bias, confirm_wait_time)"
					+ " VALUES (?, ?, ?, ?, ?)");
			
			for(CmpcontrolType control : controls.getCmpcontrol())
			{
				int idx = 1;
				ps.setString(idx++, control.getName());
				ps.setBoolean(idx++, control.isRequireConfirmCert());
				ps.setBoolean(idx++, control.isSendCaCert());
				ps.setInt(idx++, control.getMessageTimeBias());
				ps.setInt(idx++, control.getConfirmWaitTime());
		
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_responder(Responders responders)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO responder (name, type, conf, cert) VALUES (?, ?, ?, ?)");
			
			for(ResponderType responder : responders.getResponder())
			{
				int idx = 1;
				ps.setString(idx++, responder.getName());
				ps.setString(idx++, responder.getType());
				ps.setString(idx++, responder.getConf());
				ps.setString(idx++, responder.getCert());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}	
	
	private void import_environment(Environments environments)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO environment (name, value) VALUES (?, ?)");	
			for(EnvironmentType environment : environments.getEnvironment())
			{
				int idx = 1;
				ps.setString(idx++, environment.getName());
				ps.setString(idx++, environment.getValue());
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_crlsigner(Crlsigners crlsigners)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO crlsigner (name, signer_type, signer_conf, signer_cert, period, overlap, include_certs_in_crl)"
					+ " VALUES (?, ?, ?, ?, ?, ?, ?)");
			
			for(CrlsignerType crlsigner : crlsigners.getCrlsigner())
			{
				int idx = 1;
				ps.setString(idx++, crlsigner.getName());
				ps.setString(idx++, crlsigner.getSignerType());
				ps.setString(idx++, crlsigner.getSignerConf());
				ps.setString(idx++, crlsigner.getSignerCert());
				ps.setInt(idx++, crlsigner.getPeriod());
				ps.setInt(idx++, crlsigner.getOverlap());
				ps.setBoolean(idx++, crlsigner.isIncludeCertsInCrl());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}	
	
	private void import_requestor(Requestors requestors)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO requestor (name, cert) VALUES (?, ?)");
			
			for(RequestorType requestor : requestors.getRequestor())
			{
				int idx = 1;
				ps.setString(idx++, requestor.getName());
				ps.setString(idx++, requestor.getCert());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}	
	
	private void import_publisher(Publishers publishers)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO publisher (name, type, conf) VALUES (?, ?, ?)");
			for(PublisherType publisher : publishers.getPublisher())
			{
				int idx = 1;
				ps.setString(idx++, publisher.getName());
				ps.setString(idx++, publisher.getType());
				ps.setString(idx++, publisher.getConf());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}	
	
	private void import_certprofile(Certprofiles certprofiles)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO certprofile (name, type, conf) VALUES (?, ?, ?)");
			for(CertprofileType certprofile : certprofiles.getCertprofile())
			{
				int idx = 1;
				ps.setString(idx++, certprofile.getName());
				ps.setString(idx++, certprofile.getType());
				ps.setString(idx++, certprofile.getConf());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_ca(Cas cas)
	throws SQLException, CertificateException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO ca (name, subject, next_serial, status, crl_uris, ocsp_uris, max_validity, "
					+ "cert, signer_type, signer_conf, crlsigner_name, "
					+ "allow_duplicate_key, allow_duplicate_subject, permissions, num_crls) "
					+ "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			for(CaType ca : cas.getCa())
			{
				String b64Cert = ca.getCert();
				X509Certificate c;
				try {
					c = IoCertUtil.parseCert(Base64.decode(b64Cert));
				} catch (Exception e) {
					LOG.error("could not parse certificate of CA {}", ca.getName());
					LOG.debug("could not parse certificate of CA " + ca.getName(), e);
					if(e instanceof CertificateException)
					{
						throw (CertificateException) e;
					}
					else
					{
						throw new CertificateException(e);
					}
				}				
				
				int idx = 1;
				ps.setString(idx++, ca.getName());
				ps.setString(idx++, c.getSubjectX500Principal().getName());
				ps.setString(idx++, ca.getNextSerial());
				ps.setString(idx++, ca.getStatus());
				ps.setString(idx++, ca.getCrlUris());
				ps.setString(idx++, ca.getOcspUris());
				ps.setInt   (idx++, ca.getMaxValidity());
				ps.setString(idx++, b64Cert);
				ps.setString(idx++, ca.getSignerType());
				ps.setString(idx++, ca.getSignerConf());
				ps.setString(idx++, ca.getCrlsignerName());
				ps.setBoolean(idx++, ca.isAllowDuplicateKey());
				ps.setBoolean(idx++, ca.isAllowDuplicateSubject());
				ps.setString(idx++, ca.getPermissions());
				
				Integer numCrls = ca.getNumCrls();
				ps.setInt(idx++, numCrls == null ? 30 : numCrls.intValue());
				
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_caalias(Caaliases caaliases)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO caalias (name, ca_name) VALUES (?, ?)");
			for(CaaliasType caalias : caaliases.getCaalias())
			{
				int idx = 1;
				ps.setString(idx++, caalias.getName());
				ps.setString(idx++, caalias.getCaName());			
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_ca_has_requestor(CaHasRequestors ca_has_requestors)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_requestor "
					+ "(ca_name, requestor_name, ra, permissions, profiles) VALUES (?, ?, ?, ?, ?)");
			
			for(CaHasRequestorType entry : ca_has_requestors.getCaHasRequestor())
			{
				int idx = 1;
				ps.setString(idx++, entry.getCaName());
				ps.setString(idx++, entry.getRequestorName());
				ps.setBoolean(idx++, entry.isRa());
				ps.setString(idx++, entry.getPermissionts());
				ps.setString(idx++, entry.getProfiles());
		
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_ca_has_publisher(CaHasPublishers ca_has_publishers)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_publisher (ca_name, publisher_name) VALUES (?, ?)");
			for(CaHasPublisherType entry : ca_has_publishers.getCaHasPublisher())
			{
				int idx = 1;
				ps.setString(idx++, entry.getCaName());
				ps.setString(idx++, entry.getPublisherName());
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	
	private void import_ca_has_certprofile(CaHasCertprofiles ca_has_certprofiles)
	throws SQLException
	{
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_certprofile (ca_name, certprofile_name) VALUES (?, ?)");
			for(CaHasCertprofileType entry : ca_has_certprofiles.getCaHasCertprofile())
			{
				int idx = 1;
				ps.setString(idx++, entry.getCaName());
				ps.setString(idx++, entry.getCertprofileName());
				ps.executeUpdate();
			}
		}finally
		{
			closeStatement(ps);
		}
	}
	

}
