/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.CAConfigurationType;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasCertprofiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasPublishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasRequestors;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Caaliases;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Cas;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Certprofiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Crlsigners;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Environments;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Publishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Requestors;
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

/**
 * @author Lijun Liao
 */

class CaConfigurationDbImporter extends DbPorter
{
    private final Unmarshaller unmarshaller;

    CaConfigurationDbImporter(DataSourceWrapper dataSource, Unmarshaller unmarshaller, String srcDir)
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
                unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_Configuration));
        CAConfigurationType caconf = root.getValue();

        if(caconf.getVersion() > VERSION)
        {
            throw new Exception("Cannot import CA configuration greater than " + VERSION + ": " + caconf.getVersion());
        }

        System.out.println("Importing CA configuration to database");
        try
        {
            import_cmpcontrol(caconf.getCmpcontrol());
            import_responder(caconf.getResponder());
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
            System.err.println("Error while importing CA configuration to database. message: " + e.getMessage());
            throw e;
        }
        System.out.println(" Imported CA configuration to database");
    }

    private void import_cmpcontrol(CmpcontrolType control)
    throws Exception
    {
        System.out.println("Importing table CMPCONTROL");
        if(control == null)
        {
            System.out.println(" Imported table CMPCONTROL: nothing to import");
            return;
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO CMPCONTROL (NAME, REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT, "
                    + " REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?)");

            try
            {
                int idx = 1;
                ps.setString(idx++, "default");
                setBoolean(ps, idx++, control.isRequireConfirmCert());
                setBoolean(ps, idx++, control.isSendCaCert());
                setBoolean(ps, idx++, control.isSendResponderCert());
                setBoolean(ps, idx++, control.isRequireMessageTime());
                ps.setInt(idx++, control.getMessageTimeBias());
                ps.setInt(idx++, control.getConfirmWaitTime());

                ps.executeUpdate();
            }catch(Exception e)
            {
                System.err.println("Error while importing CMPCONTROL");
                throw e;
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CMPCONTROL");
    }

    private void import_responder(ResponderType responder)
    throws Exception
    {
        System.out.println("Importing table RESPONDER");
        if(responder == null)
        {
            System.out.println("Imported table RESPONDER: nothing to import");
            return;
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO RESPONDER (NAME, TYPE, CONF, CERT) VALUES (?, ?, ?, ?)");

            try
            {
                int idx = 1;
                ps.setString(idx++, "default");
                ps.setString(idx++, responder.getType());
                ps.setString(idx++, responder.getConf());
                ps.setString(idx++, responder.getCert());

                ps.executeUpdate();
            }catch(Exception e)
            {
                System.err.println("Error while importing RESPONDER");
                throw e;
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table RESPONDER");
    }

    private void import_environment(Environments environments)
    throws Exception
    {
        System.out.println("Importing table ENVIRONMENT");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)");
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
                    System.err.println("Error while importing ENVIRONMENT with NAME=" + environment.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table ENVIRONMENT");
    }

    private void import_crlsigner(Crlsigners crlsigners)
    throws Exception
    {
        System.out.println("Importing table CRLSIGNER");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO CRLSIGNER (NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL)" +
                    " VALUES (?, ?, ?, ?, ?)");

            for(CrlsignerType crlsigner : crlsigners.getCrlsigner())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, crlsigner.getName());
                    ps.setString(idx++, crlsigner.getSignerType());
                    ps.setString(idx++, crlsigner.getSignerConf());
                    ps.setString(idx++, crlsigner.getSignerCert());
                    ps.setString(idx++, crlsigner.getCrlControl());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CRLSIGNER with NAME=" + crlsigner.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CRLSIGNER");
    }

    private void import_requestor(Requestors requestors)
    throws Exception
    {
        System.out.println("Importing table REQUESTOR");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO REQUESTOR (NAME, CERT) VALUES (?, ?)");

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
                    System.err.println("Error while importing REQUESTOR with NAME=" + requestor.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table REQUESTOR");
    }

    private void import_publisher(Publishers publishers)
    throws Exception
    {
        System.out.println("Importing table PUBLISHER");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO PUBLISHER (NAME, TYPE, CONF) VALUES (?, ?, ?)");
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
                    System.err.println("Error while importing PUBLISHER with NAME=" + publisher.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table PUBLISHER");
    }

    private void import_certprofile(Certprofiles certprofiles)
    throws Exception
    {
        System.out.println("Importing table CERTPROFILE");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CERTPROFILE (NAME, TYPE, CONF) VALUES (?, ?, ?)");
            for(CertprofileType certprofile : certprofiles.getCertprofile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, certprofile.getName());
                    ps.setString(idx++, certprofile.getType());

                    String conf = certprofile.getConf();
                    if(conf == null)
                    {
                        String confFilename = certprofile.getConfFile();
                        if(confFilename != null)
                        {
                            File confFile = new File(baseDir, confFilename);
                            conf = new String(IoCertUtil.read(confFile));
                        }
                    }
                    ps.setString(idx++, conf);

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CERTPROFILE with NAME=" + certprofile.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CERTPROFILE");
    }

    private void import_ca(Cas cas)
    throws Exception
    {
        System.out.println("Importing table CA");
        PreparedStatement ps = null;
        try
        {
            StringBuilder sqlBuilder = new StringBuilder();
            sqlBuilder.append("INSERT INTO CA (NAME, SUBJECT, NEXT_SERIAL, STATUS,");
            sqlBuilder.append(" CRL_URIS, DELTA_CRL_URIS, OCSP_URIS, MAX_VALIDITY,");
            sqlBuilder.append(" CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME,");
            sqlBuilder.append(" DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS,");
            sqlBuilder.append(" EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME, VALIDITY_MODE,");
            sqlBuilder.append(" LAST_CRL_INTERVAL, LAST_CRL_INTERVAL_DATE)");
            sqlBuilder.append(" VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

            ps = prepareStatement(sqlBuilder.toString());

            for(CaType ca : cas.getCa())
            {
                try
                {
                    String b64Cert = ca.getCert();
                    X509Certificate c = IoCertUtil.parseCert(Base64.decode(b64Cert));

                    int idx = 1;
                    ps.setString(idx++, ca.getName().toUpperCase());
                    ps.setString(idx++, IoCertUtil.canonicalizeName(c.getSubjectX500Principal()));
                    ps.setLong(idx++, ca.getNextSerial());
                    ps.setString(idx++, ca.getStatus());
                    ps.setString(idx++, ca.getCrlUris());
                    ps.setString(idx++, ca.getDeltaCrlUris());
                    ps.setString(idx++, ca.getOcspUris());
                    ps.setInt   (idx++, ca.getMaxValidity());
                    ps.setString(idx++, b64Cert);
                    ps.setString(idx++, ca.getSignerType());
                    ps.setString(idx++, ca.getSignerConf());
                    ps.setString(idx++, ca.getCrlsignerName());
                    ps.setInt(idx++, ca.getDuplicateKeyMode());
                    ps.setInt(idx++, ca.getDuplicateSubjectMode());
                    ps.setString(idx++, ca.getPermissions());
                    Integer numCrls = ca.getNumCrls();
                    ps.setInt(idx++, numCrls == null ? 30 : numCrls.intValue());
                    ps.setInt(idx++, ca.getExpirationPeriod());
                    setBoolean(ps, idx++, ca.isRevoked());
                    setInt(ps, idx++, ca.getRevReason());
                    setLong(ps, idx++, ca.getRevTime());
                    setLong(ps, idx++, ca.getRevInvalidityTime());
                    ps.setString(idx++, ca.getValidityMode());
                    setInt(ps, idx++, ca.getLastCrlInterval());
                    setLong(ps, idx++, ca.getLastCrlIntervalDate());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CA with NAME=" + ca.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table CA");
    }

    private void import_caalias(Caaliases caaliases)
    throws Exception
    {
        System.out.println("Importing table CAALIAS");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)");
            for(CaaliasType caalias : caaliases.getCaalias())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, caalias.getName());
                    ps.setString(idx++, caalias.getCaName().toUpperCase());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CAALIAS with NAME=" + caalias.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CAALIAS");
    }

    private void import_ca_has_requestor(CaHasRequestors ca_has_requestors)
    throws Exception
    {
        System.out.println("Importing table CA_HAS_REQUESTOR");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_REQUESTOR "
                    + "(CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)");

            for(CaHasRequestorType entry : ca_has_requestors.getCaHasRequestor())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getRequestorName());
                    setBoolean(ps, idx++, entry.isRa());
                    ps.setString(idx++, entry.getPermissions());
                    ps.setString(idx++, entry.getProfiles());

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CA_HAS_REQUESTOR with CA_NAME=" + entry.getCaName() +
                            " and requestor_name=" + entry.getRequestorName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CA_HAS_REQUESTOR");
    }

    private void import_ca_has_publisher(CaHasPublishers ca_has_publishers)
    throws Exception
    {
        System.out.println("Importing table CA_HAS_PUBLISHER");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_PUBLISHER (CA_NAME, PUBLISHER_NAME) VALUES (?, ?)");
            for(CaHasPublisherType entry : ca_has_publishers.getCaHasPublisher())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getPublisherName());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CA_HAS_PUBLISHER with CA_NAME=" + entry.getCaName() +
                            " and publisher_name=" + entry.getPublisherName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CA_HAS_PUBLISHER");
    }

    private void import_ca_has_certprofile(CaHasCertprofiles ca_has_certprofiles)
    throws Exception
    {
        System.out.println("Importing table CA_HAS_CERTPROFILE");
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_CERTPROFILE (CA_NAME, CERTPROFILE_NAME) VALUES (?, ?)");
            for(CaHasCertprofileType entry : ca_has_certprofiles.getCaHasCertprofile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getCertprofileName());
                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CA_HAS_CERTPROFILE with CA_NAME=" + entry.getCaName() +
                            " and certprofile_name=" + entry.getCertprofileName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table CA_HAS_CERTPROFILE");
    }

}
