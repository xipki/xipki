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

package org.xipki.dbtool;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xipki.common.ParamChecker;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
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

/**
 * @author Lijun Liao
 */

class CaConfigurationDbExporter extends DbPorter
{
    private final Marshaller marshaller;
    private final int dbSchemaVersion;

    CaConfigurationDbExporter(DataSourceWrapper dataSource, Marshaller marshaller, String destDir)
    throws DataAccessException, PasswordResolverException, IOException
    {
        super(dataSource, destDir);
        ParamChecker.assertNotNull("marshaller", marshaller);
        this.marshaller = marshaller;
        this.dbSchemaVersion = getDbSchemaVersion();
    }

    public void export()
    throws Exception
    {
        CAConfigurationType caconf = new CAConfigurationType();
        caconf.setVersion(VERSION);

        System.out.println("exporting CA configuration from database");

        export_cmpcontrol(caconf);
        export_responder(caconf);
        export_environment(caconf);
        export_crlsigner(caconf);
        export_requestor(caconf);
        export_publisher(caconf);
        export_ca(caconf);
        export_certprofile(caconf);
        export_caalias(caconf);
        export_ca_has_requestor(caconf);
        export_ca_has_publisher(caconf);
        export_ca_has_certprofile(caconf);

        JAXBElement<CAConfigurationType> root = new ObjectFactory().createCAConfiguration(caconf);
        try
        {
            marshaller.marshal(root, new File(baseDir, FILENAME_CA_Configuration));
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }

        System.out.println(" exported CA configuration from database");
    }

    private void export_cmpcontrol(CAConfigurationType caconf)
    throws DataAccessException
    {
        Cmpcontrols cmpcontrols = new Cmpcontrols();
        caconf.setCmpcontrols(cmpcontrols);
        System.out.println("exporting table CMPCONTROL");
        final String sql = "SELECT NAME, REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT, "
                + " REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME"
                + " FROM CMPCONTROL";
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                boolean requireConfirmCert = rs.getBoolean("REQUIRE_CONFIRM_CERT");
                boolean sendCaCert = rs.getBoolean("SEND_CA_CERT");
                boolean sendResponderCert = rs.getBoolean("SEND_RESPONDER_CERT");
                boolean requireMessageTime = rs.getBoolean("REQUIRE_MESSAGE_TIME");
                int messageTimeBias = rs.getInt("MESSAGE_TIME_BIAS");
                int confirmWaitTime = rs.getInt("CONFIRM_WAIT_TIME");

                CmpcontrolType cmpcontrol = new CmpcontrolType();
                cmpcontrols.getCmpcontrol().add(cmpcontrol);

                cmpcontrol.setName(name);
                cmpcontrol.setRequireConfirmCert(requireConfirmCert);
                cmpcontrol.setSendCaCert(sendCaCert);
                cmpcontrol.setSendResponderCert(sendResponderCert);
                cmpcontrol.setRequireMessageTime(requireMessageTime);
                cmpcontrol.setMessageTimeBias(messageTimeBias);
                cmpcontrol.setConfirmWaitTime(confirmWaitTime);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table CMPCONTROL");
    }

    private void export_environment(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table ENVIRONMENT");
        Environments environments = new Environments();
        final String sql = "SELECT NAME, VALUE2 FROM ENVIRONMENT";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();

            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");

                EnvironmentType environment = new EnvironmentType();
                environment.setName(name);
                environment.setValue(value);
                environments.getEnvironment().add(environment);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setEnvironments(environments);
        System.out.println(" exported table ENVIRONMENT");
    }

    private void export_crlsigner(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CRLSIGNER");
        Crlsigners crlsigners = new Crlsigners();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL");
        sqlBuilder.append(" FROM CRLSIGNER");
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String signer_cert = rs.getString("SIGNER_CERT");
                String crl_control = rs.getString("CRL_CONTROL");

                CrlsignerType crlsigner = new CrlsignerType();
                crlsigner.setName(name);
                crlsigner.setSignerType(signer_type);
                crlsigner.setSignerConf(signer_conf);
                crlsigner.setSignerCert(signer_cert);
                crlsigner.setCrlControl(crl_control);

                crlsigners.getCrlsigner().add(crlsigner);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCrlsigners(crlsigners);
        System.out.println(" exported table CRLSIGNER");
    }

    private void export_caalias(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CAALIAS");
        Caaliases caaliases = new Caaliases();
        final String sql = "SELECT NAME, CA_NAME FROM CAALIAS";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String caName = rs.getString("CA_NAME");

                CaaliasType caalias = new CaaliasType();
                caalias.setName(name);
                caalias.setCaName(caName);

                caaliases.getCaalias().add(caalias);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCaaliases(caaliases);
        System.out.println(" exported table CAALIAS");
    }

    private void export_requestor(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table REQUESTOR");
        Requestors requestors = new Requestors();
        final String sql = "SELECT NAME, CERT FROM REQUESTOR";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String cert = rs.getString("CERT");

                RequestorType requestor = new RequestorType();
                requestor.setName(name);
                requestor.setCert(cert);

                requestors.getRequestor().add(requestor);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setRequestors(requestors);
        System.out.println(" exported table REQUESTOR");
    }

    private void export_responder(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table RESPONDER");
        ResponderType responder = null;
        final String sql = "SELECT TYPE, CERT, CONF FROM RESPONDER";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");
                String cert = rs.getString("CERT");

                responder = new ResponderType();
                responder.setType(type);
                responder.setConf(conf);
                responder.setCert(cert);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setResponder(responder);
        System.out.println(" exported table RESPONDER");
    }

    private void export_publisher(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table PUBLISHER");
        Publishers publishers = new Publishers();
        final String sql = "SELECT NAME, TYPE, CONF FROM PUBLISHER";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                PublisherType publisher = new PublisherType();
                publisher.setName(name);
                publisher.setType(type);
                publisher.setConf(conf);

                publishers.getPublisher().add(publisher);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setPublishers(publishers);
        System.out.println(" exported table PUBLISHER");
    }

    private void export_certprofile(CAConfigurationType caconf)
    throws DataAccessException, IOException
    {
        System.out.println("exporting table CERTPROFILE");
        Certprofiles certprofiles = new Certprofiles();
        StringBuilder sqlBuilder = new StringBuilder("SELECT");
        sqlBuilder.append(" NAME");
        if(dbSchemaVersion > 1)
        {
            sqlBuilder.append(", ART");
        }
        sqlBuilder.append(", TYPE, CONF FROM CERTPROFILE");
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                int art;
                if(dbSchemaVersion == 1)
                {
                    art = 1; // X.509
                }
                else
                {
                    art = rs.getInt("ART");
                }
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                CertprofileType certprofile = new CertprofileType();
                certprofile.setName(name);
                certprofile.setArt(art);
                certprofile.setType(type);
                if(conf != null && conf.length() > 200)
                {
                    String filepath = "certprofile" + File.separator + name + ".conf";
                    File f = new File(baseDir, filepath);
                    IoUtil.save(f, conf.getBytes());
                    certprofile.setConfFile(filepath);
                }
                else
                {
                    certprofile.setConf(conf);
                }

                certprofiles.getCertprofile().add(certprofile);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCertprofiles(certprofiles);
        System.out.println(" exported table CERTPROFILE");
    }

    private void export_ca(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CA");
        Cas cas = new Cas();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT NAME,");
        sqlBuilder.append(" NEXT_SERIAL, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY,");
        sqlBuilder.append(" CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, CMPCONTROL_NAME,");
        sqlBuilder.append(" DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS,");
        sqlBuilder.append(" EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME,");
        sqlBuilder.append(" DELTA_CRL_URIS, VALIDITY_MODE");
        if(dbSchemaVersion > 1)
        {
            sqlBuilder.append(", ART, NEXT_CRLNO, CMPCONTROL_NAME, ADD_CONTROL");
        }
        sqlBuilder.append(" FROM CA");

        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");

                int art;
                int next_crlNo;
                String cmpcontrol_name;
                String addControl;
                if(dbSchemaVersion == 1)
                {
                    art = 1; // X.509
                    next_crlNo = 1;
                    cmpcontrol_name = "default";
                    addControl = null;
                }
                else
                {
                    art = rs.getInt("ART");
                    next_crlNo = rs.getInt("NEXT_CRLNO");
                    cmpcontrol_name = rs.getString("CMPCONTROL_NAME");
                    addControl = rs.getString("ADD_CONTROL");
                }

                long next_serial = rs.getLong("NEXT_SERIAL");

                String status = rs.getString("STATUS");
                String crl_uris = rs.getString("CRL_URIS");
                String delta_crl_uris = rs.getString("DELTA_CRL_URIS");

                String ocsp_uris = rs.getString("OCSP_URIS");
                String max_validity = rs.getString("MAX_VALIDITY");
                String cert = rs.getString("CERT");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String crlsigner_name = rs.getString("CRLSIGNER_NAME");
                int duplicateKeyMode = rs.getInt("DUPLICATE_KEY_MODE");
                int duplicateSubjectMode = rs.getInt("DUPLICATE_SUBJECT_MODE");
                String permissions = rs.getString("PERMISSIONS");
                int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");
                String validityMode = rs.getString("VALIDITY_MODE");

                CaType ca = new CaType();
                ca.setName(name);
                ca.setArt(art);
                ca.setNextSerial(next_serial);
                ca.setNextCrlNo(next_crlNo);
                ca.setStatus(status);
                ca.setCrlUris(crl_uris);
                ca.setDeltaCrlUris(delta_crl_uris);
                ca.setOcspUris(ocsp_uris);
                ca.setMaxValidity(max_validity);
                ca.setCert(cert);
                ca.setSignerType(signer_type);
                ca.setSignerConf(signer_conf);
                ca.setCrlsignerName(crlsigner_name);
                ca.setCmpcontrolName(cmpcontrol_name);
                ca.setDuplicateKeyMode(duplicateKeyMode);
                ca.setDuplicateSubjectMode(duplicateSubjectMode);
                ca.setPermissions(permissions);
                ca.setExpirationPeriod(expirationPeriod);
                ca.setValidityMode(validityMode);
                ca.setAddControl(addControl);

                int numCrls = rs.getInt("num_crls");
                ca.setNumCrls(numCrls);

                boolean revoked = rs.getBoolean("REVOKED");
                ca.setRevoked(revoked);
                if(revoked)
                {
                    int reason = rs.getInt("REV_REASON");
                    long rev_time = rs.getLong("REV_TIME");
                    long rev_invalidity_time = rs.getLong("REV_INVALIDITY_TIME");
                    ca.setRevReason(reason);
                    ca.setRevTime(rev_time);
                    ca.setRevInvalidityTime(rev_invalidity_time);
                }

                cas.getCa().add(ca);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCas(cas);
        System.out.println(" exported table CA");
    }

    private void export_ca_has_requestor(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CA_HAS_REQUESTOR");
        CaHasRequestors ca_has_requestors = new CaHasRequestors();
        final String sql = "SELECT CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES FROM CA_HAS_REQUESTOR";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String requestor_name = rs.getString("REQUESTOR_NAME");
                boolean ra = rs.getBoolean("RA");
                String permissions = rs.getString("PERMISSIONS");
                String profiles = rs.getString("PROFILES");

                CaHasRequestorType ca_has_requestor = new CaHasRequestorType();
                ca_has_requestor.setCaName(ca_name);
                ca_has_requestor.setRequestorName(requestor_name);
                ca_has_requestor.setRa(ra);
                ca_has_requestor.setPermissions(permissions);
                ca_has_requestor.setProfiles(profiles);

                ca_has_requestors.getCaHasRequestor().add(ca_has_requestor);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasRequestors(ca_has_requestors);
        System.out.println(" exported table CA_HAS_REQUESTOR");
    }

    private void export_ca_has_publisher(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CA_HAS_PUBLISHER");
        CaHasPublishers ca_has_publishers = new CaHasPublishers();
        final String sql = "SELECT CA_NAME, PUBLISHER_NAME FROM CA_HAS_PUBLISHER";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String publisher_name = rs.getString("PUBLISHER_NAME");

                CaHasPublisherType ca_has_publisher = new CaHasPublisherType();
                ca_has_publisher.setCaName(ca_name);
                ca_has_publisher.setPublisherName(publisher_name);;

                ca_has_publishers.getCaHasPublisher().add(ca_has_publisher);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasPublishers(ca_has_publishers);
        System.out.println(" exported table CA_HAS_PUBLISHER");
    }

    private void export_ca_has_certprofile(CAConfigurationType caconf)
    throws DataAccessException
    {
        System.out.println("exporting table CA_HAS_CERTPROFILE");
        CaHasCertprofiles ca_has_certprofiles = new CaHasCertprofiles();
        final String sql = "SELECT CA_NAME, CERTPROFILE_NAME FROM CA_HAS_CERTPROFILE";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String certprofile_name = rs.getString("CERTPROFILE_NAME");

                CaHasCertprofileType ca_has_certprofile = new CaHasCertprofileType();
                ca_has_certprofile.setCaName(ca_name);
                ca_has_certprofile.setCertprofileName(certprofile_name);

                ca_has_certprofiles.getCaHasCertprofile().add(ca_has_certprofile);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasCertprofiles(ca_has_certprofiles);
        System.out.println(" exported table CA_HAS_CERTPROFILE");
    }

}
