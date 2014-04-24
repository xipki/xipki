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
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
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

class CaConfigurationDbImporter extends DbPorter
{
    private final Unmarshaller unmarshaller;

    CaConfigurationDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir)
    throws SQLException, PasswordResolverException, IOException
    {
        super(dataSource, srcDir);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
    }

    public void importToDB()
    throws Exception
    {
        @SuppressWarnings("unchecked")
        JAXBElement<CAConfigurationType> root = (JAXBElement<CAConfigurationType>)
                unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_CA_Configuration));
        CAConfigurationType caconf = root.getValue();

        System.out.println("Importing CA configuration to database");
        try
        {
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
        }catch(Exception e)
        {
            System.err.println("Error while imporing CA configuration to database. message: " + e.getMessage());
            throw e;
        }
        System.out.println("Imported CA configuration to database");
    }

    private void import_cmpcontrol(Cmpcontrols controls)
    throws Exception
    {
        System.out.println("Importing table cmpcontrol");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO cmpcontrol (name, require_confirm_cert, send_ca_cert, "
                    + " message_time_bias, confirm_wait_time)"
                    + " VALUES (?, ?, ?, ?, ?)");

            for(CmpcontrolType control : controls.getCmpcontrol())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, control.getName());
                    ps.setBoolean(idx++, control.isRequireConfirmCert());
                    ps.setBoolean(idx++, control.isSendCaCert());
                    ps.setInt(idx++, control.getMessageTimeBias());
                    ps.setInt(idx++, control.getConfirmWaitTime());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing cmpcontrol with name=" + control.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table cmpcontrol");
    }

    private void import_responder(Responders responders)
    throws Exception
    {
        System.out.println("Importing table responder");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO responder (name, type, conf, cert) VALUES (?, ?, ?, ?)");

            for(ResponderType responder : responders.getResponder())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, responder.getName());
                    ps.setString(idx++, responder.getType());
                    ps.setString(idx++, responder.getConf());
                    ps.setString(idx++, responder.getCert());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing responder with name=" + responder.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table responder");
    }

    private void import_environment(Environments environments)
    throws Exception
    {
        System.out.println("Importing table environment");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO environment (name, value) VALUES (?, ?)");
            for(EnvironmentType environment : environments.getEnvironment())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, environment.getName());
                    ps.setString(idx++, environment.getValue());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing environment with name=" + environment.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table environment");
    }

    private void import_crlsigner(Crlsigners crlsigners)
    throws Exception
    {
        System.out.println("Importing table crlsigner");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO crlsigner (name, signer_type, signer_conf, signer_cert, period, overlap, include_certs_in_crl)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?)");

            for(CrlsignerType crlsigner : crlsigners.getCrlsigner())
            {
                try
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
                }catch(Exception e)
                {
                    System.err.println("Error while importing crlsigner with name=" + crlsigner.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table crlsigner");
    }

    private void import_requestor(Requestors requestors)
    throws Exception
    {
        System.out.println("Importing table requestor");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO requestor (name, cert) VALUES (?, ?)");

            for(RequestorType requestor : requestors.getRequestor())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, requestor.getName());
                    ps.setString(idx++, requestor.getCert());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing requestor with name=" + requestor.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table requestor");
    }

    private void import_publisher(Publishers publishers)
    throws Exception
    {
        System.out.println("Importing table publisher");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO publisher (name, type, conf) VALUES (?, ?, ?)");
            for(PublisherType publisher : publishers.getPublisher())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, publisher.getName());
                    ps.setString(idx++, publisher.getType());
                    ps.setString(idx++, publisher.getConf());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing publisher with name=" + publisher.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table publisher");
    }

    private void import_certprofile(Certprofiles certprofiles)
    throws Exception
    {
        System.out.println("Importing table certprofile");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO certprofile (name, type, conf) VALUES (?, ?, ?)");
            for(CertprofileType certprofile : certprofiles.getCertprofile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, certprofile.getName());
                    ps.setString(idx++, certprofile.getType());
                    ps.setString(idx++, certprofile.getConf());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing certprofile with name=" + certprofile.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table certprofile");
    }

    private void import_ca(Cas cas)
    throws Exception
    {
        System.out.println("Importing table ca");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO ca (name, subject, next_serial, status, crl_uris, ocsp_uris, max_validity, "
                    + "cert, signer_type, signer_conf, crlsigner_name, "
                    + "allow_duplicate_key, allow_duplicate_subject, permissions, num_crls) "
                    + "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

            for(CaType ca : cas.getCa())
            {
                try
                {
                    String b64Cert = ca.getCert();
                    X509Certificate c = IoCertUtil.parseCert(Base64.decode(b64Cert));

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
                }catch(Exception e)
                {
                    System.err.println("Error while importing ca with name=" + ca.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Importing table ca");
    }

    private void import_caalias(Caaliases caaliases)
    throws Exception
    {
        System.out.println("Importing table caalias");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO caalias (name, ca_name) VALUES (?, ?)");
            for(CaaliasType caalias : caaliases.getCaalias())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, caalias.getName());
                    ps.setString(idx++, caalias.getCaName());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing caalias with name=" + caalias.getName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Importing table caalias");
    }

    private void import_ca_has_requestor(CaHasRequestors ca_has_requestors)
    throws Exception
    {
        System.out.println("Importing table ca_has_requestor");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO ca_has_requestor "
                    + "(ca_name, requestor_name, ra, permissions, profiles) VALUES (?, ?, ?, ?, ?)");

            for(CaHasRequestorType entry : ca_has_requestors.getCaHasRequestor())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName());
                    ps.setString(idx++, entry.getRequestorName());
                    ps.setBoolean(idx++, entry.isRa());
                    ps.setString(idx++, entry.getPermissionts());
                    ps.setString(idx++, entry.getProfiles());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing ca_has_requestor with ca_name=" + entry.getCaName() +
                            " and requestor_name=" + entry.getRequestorName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table ca_has_requestor");
    }

    private void import_ca_has_publisher(CaHasPublishers ca_has_publishers)
    throws Exception
    {
        System.out.println("Importing table ca_has_publisher");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO ca_has_publisher (ca_name, publisher_name) VALUES (?, ?)");
            for(CaHasPublisherType entry : ca_has_publishers.getCaHasPublisher())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName());
                    ps.setString(idx++, entry.getPublisherName());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing ca_has_publisher with ca_name=" + entry.getCaName() +
                            " and publisher_name=" + entry.getPublisherName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table ca_has_publisher");
    }

    private void import_ca_has_certprofile(CaHasCertprofiles ca_has_certprofiles)
    throws Exception
    {
        System.out.println("Importing table ca_has_certprofile");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO ca_has_certprofile (ca_name, certprofile_name) VALUES (?, ?)");
            for(CaHasCertprofileType entry : ca_has_certprofiles.getCaHasCertprofile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName());
                    ps.setString(idx++, entry.getCertprofileName());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing ca_has_certprofile with ca_name=" + entry.getCaName() +
                            " and certprofile_name=" + entry.getCertprofileName());
                    throw e;
                }
            }
        }finally
        {
            closeStatement(ps);
        }
        System.out.println("Imported table ca_has_certprofile");
    }

}
