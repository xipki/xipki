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

package org.xipki.dbtool.ca;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.X509Util;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbi.ca.jaxb.CAConfigurationType;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasProfiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasPublishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.CaHasRequestors;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Caaliases;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Cas;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Cmpcontrols;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Crlsigners;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Environments;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Profiles;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Publishers;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Requestors;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Responders;
import org.xipki.dbi.ca.jaxb.CAConfigurationType.Sceps;
import org.xipki.dbi.ca.jaxb.CaHasProfileType;
import org.xipki.dbi.ca.jaxb.CaHasPublisherType;
import org.xipki.dbi.ca.jaxb.CaHasRequestorType;
import org.xipki.dbi.ca.jaxb.CaType;
import org.xipki.dbi.ca.jaxb.CaaliasType;
import org.xipki.dbi.ca.jaxb.CmpcontrolType;
import org.xipki.dbi.ca.jaxb.CrlsignerType;
import org.xipki.dbi.ca.jaxb.EnvironmentType;
import org.xipki.dbi.ca.jaxb.ProfileType;
import org.xipki.dbi.ca.jaxb.PublisherType;
import org.xipki.dbi.ca.jaxb.RequestorType;
import org.xipki.dbi.ca.jaxb.ResponderType;
import org.xipki.dbi.ca.jaxb.ScepType;
import org.xipki.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

class CaConfigurationDbImporter extends DbPorter
{
    private final Unmarshaller unmarshaller;

    CaConfigurationDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir)
    throws DataAccessException, PasswordResolverException, IOException
    {
        super(dataSource, srcDir);
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
    }

    public void importToDB()
    throws Exception
    {
        CAConfigurationType caconf;
        try
        {
            @SuppressWarnings("unchecked")
            JAXBElement<CAConfigurationType> root = (JAXBElement<CAConfigurationType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_Configuration));
            caconf = root.getValue();
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }

        if(caconf.getVersion() > VERSION)
        {
            throw new InvalidInputException("could not import CA configuration greater than " +
                    VERSION + ": " + caconf.getVersion());
        }

        System.out.println("importing CA configuration to database");
        try
        {
            import_cmpcontrol(caconf.getCmpcontrols());
            import_responder(caconf.getResponders());
            import_environment(caconf.getEnvironments());
            import_requestor(caconf.getRequestors());
            import_publisher(caconf.getPublishers());
            import_profile(caconf.getProfiles());
            import_crlsigner(caconf.getCrlsigners());
            import_ca(caconf.getCas());
            import_caalias(caconf.getCaaliases());
            import_ca_has_requestor(caconf.getCaHasRequestors());
            import_ca_has_publisher(caconf.getCaHasPublishers());
            import_ca_has_certprofile(caconf.getCaHasProfiles());
            import_scep(caconf.getSceps());
        }catch(Exception e)
        {
            System.err.println("error while importing CA configuration to database. message: " + e.getMessage());
            throw e;
        }
        System.out.println(" imported CA configuration to database");
    }

    private void import_cmpcontrol(
            final Cmpcontrols controls)
    throws DataAccessException
    {
        System.out.println("importing table CMPCONTROL");
        final String sql = "INSERT INTO CMPCONTROL (NAME, CONF) VALUES (?, ?)";

        if(controls != null && CollectionUtil.isNotEmpty(controls.getCmpcontrol()))
        {
            PreparedStatement ps = null;
            try
            {
                ps = prepareStatement(sql);

                for(CmpcontrolType control : controls.getCmpcontrol())
                {
                    try
                    {
                        int idx = 1;
                        ps.setString(idx++, control.getName());
                        ps.setString(idx++, control.getConf());

                        ps.executeUpdate();
                    }catch(SQLException e)
                    {
                        System.err.println("error while importing CMPCONTROL " + control.getName());
                        throw translate(sql, e);
                    }
                }
            }finally
            {
                releaseResources(ps, null);
            }
        }
        System.out.println(" imported table CMPCONTROL");
    }

    private void import_responder(
            final Responders responders)
    throws DataAccessException
    {
        System.out.println("importing table RESPONDER");
        if(responders == null)
        {
            System.out.println(" imported table RESPONDER: nothing to import");
            return;
        }
        final String sql = "INSERT INTO RESPONDER (NAME, TYPE, CONF, CERT) VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);

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
                }catch(SQLException e)
                {
                    System.err.println("error while importing CRLSIGNER with NAME=" + responder.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table RESPONDER");
    }

    private void import_environment(
            final Environments environments)
    throws DataAccessException
    {
        System.out.println("importing table ENVIRONMENT");
        final String sql = "INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            for(EnvironmentType environment : environments.getEnvironment())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, environment.getName());
                    ps.setString(idx++, environment.getValue());
                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing ENVIRONMENT with NAME=" + environment.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table ENVIRONMENT");
    }

    private void import_crlsigner(
            final Crlsigners crlsigners)
    throws DataAccessException
    {
        System.out.println("importing table CRLSIGNER");
        final String sql = "INSERT INTO CRLSIGNER (NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL)" +
                " VALUES (?, ?, ?, ?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);

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
                }catch(SQLException e)
                {
                    System.err.println("error while importing CRLSIGNER with NAME=" + crlsigner.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CRLSIGNER");
    }

    private void import_requestor(
            final Requestors requestors)
    throws DataAccessException
    {
        System.out.println("importing table REQUESTOR");
        final String sql = "INSERT INTO REQUESTOR (NAME, CERT) VALUES (?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);

            for(RequestorType requestor : requestors.getRequestor())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, requestor.getName());
                    ps.setString(idx++, requestor.getCert());

                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing REQUESTOR with NAME=" + requestor.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table REQUESTOR");
    }

    private void import_publisher(
            final Publishers publishers)
    throws DataAccessException
    {
        System.out.println("importing table PUBLISHER");
        final String sql = "INSERT INTO PUBLISHER (NAME, TYPE, CONF) VALUES (?, ?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            for(PublisherType publisher : publishers.getPublisher())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, publisher.getName());
                    ps.setString(idx++, publisher.getType());
                    ps.setString(idx++, publisher.getConf());

                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing PUBLISHER with NAME=" + publisher.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table PUBLISHER");
    }

    private void import_profile(
            final Profiles profiles)
    throws DataAccessException, IOException
    {
        System.out.println("importing table PROFILE");
        final String sql = "INSERT INTO PROFILE (NAME, ART, TYPE, CONF) VALUES (?, ?, ?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            for(ProfileType certprofile : profiles.getProfile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, certprofile.getName());
                    int art = certprofile.getArt() == null ? 1 : certprofile.getArt();
                    ps.setInt(idx++, art);
                    ps.setString(idx++, certprofile.getType());

                    String conf = certprofile.getConf();
                    if(conf == null)
                    {
                        String confFilename = certprofile.getConfFile();
                        if(confFilename != null)
                        {
                            File confFile = new File(baseDir, confFilename);
                            conf = new String(IoUtil.read(confFile));
                        }
                    }
                    ps.setString(idx++, conf);

                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing PROFILE with NAME=" + certprofile.getName());
                    throw translate(sql, e);
                }catch(IOException e)
                {
                    System.err.println("error while importing PROFILE with NAME=" + certprofile.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table PROFILE");
    }

    private void import_ca(
            final Cas cas)
    throws DataAccessException, CertificateException, IOException
    {
        System.out.println("importing table CA");
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CA (NAME, ART, SUBJECT, NEXT_SERIAL, NEXT_CRLNO, STATUS,");
        sqlBuilder.append(" CRL_URIS, DELTACRL_URIS, OCSP_URIS, CACERT_URIS, MAX_VALIDITY,");
        sqlBuilder.append(" CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, RESPONDER_NAME, CMPCONTROL_NAME,");
        sqlBuilder.append(" DUPLICATE_KEY, DUPLICATE_SUBJECT, PERMISSIONS, NUM_CRLS,");
        sqlBuilder.append(" EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INV_TIME, VALIDITY_MODE,");
        sqlBuilder.append(" EXTRA_CONTROL)");
        sqlBuilder.append(" VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);

            for(CaType ca : cas.getCa())
            {
                int art = ca.getArt() == null ? 1 : ca.getArt();

                try
                {
                    String b64Cert = ca.getCert();
                    X509Certificate c = X509Util.parseCert(Base64.decode(b64Cert));

                    int idx = 1;
                    ps.setString(idx++, ca.getName().toUpperCase());
                    ps.setInt(idx++, art);
                    ps.setString(idx++, X509Util.getRFC4519Name(c.getSubjectX500Principal()));
                    ps.setLong(idx++, ca.getNextSerial());
                    ps.setInt(idx++, ca.getNextCrlNo());
                    ps.setString(idx++, ca.getStatus());
                    ps.setString(idx++, ca.getCrlUris());
                    ps.setString(idx++, ca.getDeltacrlUris());
                    ps.setString(idx++, ca.getOcspUris());
                    ps.setString(idx++, ca.getCacertUris());
                    ps.setString(idx++, ca.getMaxValidity());
                    ps.setString(idx++, b64Cert);
                    ps.setString(idx++, ca.getSignerType());
                    ps.setString(idx++, ca.getSignerConf());
                    ps.setString(idx++, ca.getCrlsignerName());
                    ps.setString(idx++, ca.getResponderName());
                    ps.setString(idx++, ca.getCmpcontrolName());
                    ps.setInt(idx++, ca.getDuplicateKey());
                    ps.setInt(idx++, ca.getDuplicateSubject());
                    ps.setString(idx++, ca.getPermissions());
                    Integer numCrls = ca.getNumCrls();
                    ps.setInt(idx++, numCrls == null ? 30 : numCrls.intValue());
                    ps.setInt(idx++, ca.getExpirationPeriod());
                    setBoolean(ps, idx++, ca.isRevoked());
                    setInt(ps, idx++, ca.getRevReason());
                    setLong(ps, idx++, ca.getRevTime());
                    setLong(ps, idx++, ca.getRevInvTime());
                    ps.setString(idx++, ca.getValidityMode());
                    ps.setString(idx++, ca.getExtraControl());

                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CA with NAME=" + ca.getName());
                    throw translate(sql, e);
                }catch(CertificateException | IOException e)
                {
                    System.err.println("error while importing CA with NAME=" + ca.getName());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CA");
    }

    private void import_caalias(
            final Caaliases caaliases)
    throws DataAccessException
    {
        System.out.println("importing table CAALIAS");
        final String sql = "INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)";
        PreparedStatement ps = prepareStatement(sql);;
        try
        {
            for(CaaliasType caalias : caaliases.getCaalias())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, caalias.getName());
                    ps.setString(idx++, caalias.getCaName().toUpperCase());
                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CAALIAS with NAME=" + caalias.getName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CAALIAS");
    }

    private void import_ca_has_requestor(
            final CaHasRequestors ca_has_requestors)
    throws DataAccessException
    {
        System.out.println("importing table CA_HAS_REQUESTOR");
        final String sql =
                "INSERT INTO CA_HAS_REQUESTOR (CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)";
        PreparedStatement ps = prepareStatement(sql);
        try
        {
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
                }catch(SQLException e)
                {
                    System.err.println("error while importing CA_HAS_REQUESTOR with CA_NAME=" + entry.getCaName() +
                            " and requestor_name=" + entry.getRequestorName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_REQUESTOR");
    }

    private void import_ca_has_publisher(
            final CaHasPublishers ca_has_publishers)
    throws Exception
    {
        System.out.println("importing table CA_HAS_PUBLISHER");
        final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_NAME, PUBLISHER_NAME) VALUES (?, ?)";
        PreparedStatement ps = prepareStatement(sql);
        try
        {
            for(CaHasPublisherType entry : ca_has_publishers.getCaHasPublisher())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getPublisherName());
                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CA_HAS_PUBLISHER with CA_NAME=" + entry.getCaName() +
                            " and publisher_name=" + entry.getPublisherName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_PUBLISHER");
    }

    private void import_ca_has_certprofile(
            final CaHasProfiles ca_has_certprofiles)
    throws DataAccessException
    {
        System.out.println("importing table CA_HAS_PROFILE");
        final String sql = "INSERT INTO CA_HAS_PROFILE (CA_NAME, PROFILE_NAME, PROFILE_LOCALNAME) VALUES (?, ?, ?)";
        PreparedStatement ps = prepareStatement(sql);
        try
        {
            for(CaHasProfileType entry : ca_has_certprofiles.getCaHasProfile())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getProfileName());
                    ps.setString(idx++, entry.getProfileLocalname());
                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CA_HAS_PROFILE with CA_NAME=" + entry.getCaName() +
                            ", profile_name=" + entry.getProfileName() +
                            " and profile_localname=" + entry.getProfileLocalname());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_PROFILE");
    }

    private void import_scep(
            final Sceps sceps)
    throws DataAccessException
    {
        System.out.println("importing table SCEP");
        final String sql = "INSERT INTO SCEP (CA_NAME, RESPONDER_TYPE, RESPONDER_CONF, "
                + "RESPONDER_CERT, CONTROL) VALUES (?, ?, ?, ?, ?)";
        PreparedStatement ps = prepareStatement(sql);
        try
        {
            for(ScepType entry : sceps.getScep())
            {
                try
                {
                    int idx = 1;
                    ps.setString(idx++, entry.getCaName().toUpperCase());
                    ps.setString(idx++, entry.getResponderType());
                    ps.setString(idx++, entry.getResponderConf());
                    ps.setString(idx++, entry.getResponderCert());
                    ps.setString(idx++, entry.getControl());
                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing SCEP with NAME=" + entry.getCaName());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table SCEP");
    }

}
