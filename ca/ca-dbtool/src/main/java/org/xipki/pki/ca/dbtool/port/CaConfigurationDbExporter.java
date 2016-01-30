/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.port;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.springframework.dao.DataAccessException;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasProfiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasPublishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasRequestors;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Caaliases;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Cmpcontrols;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Crlsigners;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Environments;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Profiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Publishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Requestors;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Responders;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType.Sceps;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaHasProfileType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaHasPublisherType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaHasRequestorType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaaliasType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CmpcontrolType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CrlsignerType;
import org.xipki.pki.ca.dbtool.jaxb.ca.EnvironmentType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ObjectFactory;
import org.xipki.pki.ca.dbtool.jaxb.ca.ProfileType;
import org.xipki.pki.ca.dbtool.jaxb.ca.PublisherType;
import org.xipki.pki.ca.dbtool.jaxb.ca.RequestorType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ResponderType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ScepType;

/**
 * @author Lijun Liao
 */

class CaConfigurationDbExporter extends DbPorter {

    private final Marshaller marshaller;

    CaConfigurationDbExporter(
            final DataSourceWrapper dataSource,
            final Marshaller marshaller,
            final String destDir,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws DataAccessException, PasswordResolverException, IOException {
        super(dataSource, destDir, stopMe, evaluateOnly);
        ParamUtil.assertNotNull("marshaller", marshaller);
        this.marshaller = marshaller;
    }

    public void export()
    throws Exception {
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
        export_profile(caconf);
        export_caalias(caconf);
        export_ca_has_requestor(caconf);
        export_ca_has_publisher(caconf);
        export_ca_has_profile(caconf);
        export_scep(caconf);

        JAXBElement<CAConfigurationType> root = new ObjectFactory().createCAConfiguration(caconf);
        try {
            marshaller.marshal(root, new File(baseDir, FILENAME_CA_Configuration));
        } catch (JAXBException e) {
            throw XMLUtil.convert(e);
        }

        System.out.println(" exported CA configuration from database");
    }

    private void export_cmpcontrol(
            final CAConfigurationType caconf)
    throws DataAccessException {
        Cmpcontrols cmpcontrols = new Cmpcontrols();
        caconf.setCmpcontrols(cmpcontrols);
        System.out.println("exporting table CMPCONTROL");

        final String sql = "SELECT NAME, CONF FROM CMPCONTROL";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String conf = rs.getString("CONF");

                CmpcontrolType cmpcontrol = new CmpcontrolType();
                cmpcontrols.getCmpcontrol().add(cmpcontrol);
                cmpcontrol.setName(name);
                cmpcontrol.setConf(conf);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table CMPCONTROL");
    } // method export_cmpcontrol

    private void export_environment(
            final CAConfigurationType caconf)
    throws DataAccessException {
        System.out.println("exporting table ENVIRONMENT");
        Environments environments = new Environments();
        final String sql = "SELECT NAME, VALUE2 FROM ENVIRONMENT";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();

            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");

                EnvironmentType environment = new EnvironmentType();
                environment.setName(name);
                environment.setValue(value);
                environments.getEnvironment().add(environment);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setEnvironments(environments);
        System.out.println(" exported table ENVIRONMENT");
    } // method export_environment

    private void export_crlsigner(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table CRLSIGNER");
        Crlsigners crlsigners = new Crlsigners();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL");
        sqlBuilder.append(" FROM CRLSIGNER");
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String signer_cert = rs.getString("SIGNER_CERT");
                String crl_control = rs.getString("CRL_CONTROL");

                CrlsignerType crlsigner = new CrlsignerType();
                crlsigner.setName(name);
                crlsigner.setSignerType(signer_type);
                crlsigner.setSignerConf(
                        buildFileOrValue(signer_conf, "ca-conf/signerconf-crlsigner-" + name));
                crlsigner.setSignerCert(
                        buildFileOrValue(signer_cert, "ca-conf/signercert-crlsigner-" + name));
                crlsigner.setCrlControl(crl_control);

                crlsigners.getCrlsigner().add(crlsigner);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCrlsigners(crlsigners);
        System.out.println(" exported table CRLSIGNER");
    } // method export_crlsigner

    private void export_caalias(
            final CAConfigurationType caconf)
    throws DataAccessException {
        System.out.println("exporting table CAALIAS");
        Caaliases caaliases = new Caaliases();
        final String sql = "SELECT NAME, CA_NAME FROM CAALIAS";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String caName = rs.getString("CA_NAME");

                CaaliasType caalias = new CaaliasType();
                caalias.setName(name);
                caalias.setCaName(caName);

                caaliases.getCaalias().add(caalias);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCaaliases(caaliases);
        System.out.println(" exported table CAALIAS");
    } // method export_caalias

    private void export_requestor(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table REQUESTOR");
        Requestors requestors = new Requestors();
        final String sql = "SELECT NAME, CERT FROM REQUESTOR";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String cert = rs.getString("CERT");

                RequestorType requestor = new RequestorType();
                requestor.setName(name);
                requestor.setCert(
                        buildFileOrValue(cert, "ca-conf/cert-requestor-" + name));

                requestors.getRequestor().add(requestor);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setRequestors(requestors);
        System.out.println(" exported table REQUESTOR");
    } // method export_requestor

    private void export_responder(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table RESPONDER");

        System.out.println("exporting table CRLSIGNER");
        Responders responders = new Responders();
        final String sql = "SELECT NAME, TYPE, CONF, CERT FROM RESPONDER";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");
                String cert = rs.getString("CERT");

                ResponderType responder = new ResponderType();
                responder.setName(name);
                responder.setType(type);
                responder.setConf(
                        buildFileOrValue(conf, "ca-conf/conf-responder-" + name));
                responder.setCert(
                        buildFileOrValue(cert, "ca-conf/cert-responder-" + name));
                responders.getResponder().add(responder);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setResponders(responders);
        System.out.println(" exported table RESPONDER");
    } // method export_responder

    private void export_publisher(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table PUBLISHER");
        Publishers publishers = new Publishers();
        final String sql = "SELECT NAME, TYPE, CONF FROM PUBLISHER";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                PublisherType publisher = new PublisherType();
                publisher.setName(name);
                publisher.setType(type);
                publisher.setConf(
                        buildFileOrValue(conf, "ca-conf/conf-publisher-" + name));

                publishers.getPublisher().add(publisher);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setPublishers(publishers);
        System.out.println(" exported table PUBLISHER");
    } // method export_publisher

    private void export_profile(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table PROFILE");
        Profiles profiles = new Profiles();
        final String sql = "SELECT NAME, ART, TYPE, CONF FROM PROFILE";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                int art = rs.getInt("ART");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                ProfileType profile = new ProfileType();
                profile.setName(name);
                profile.setArt(art);
                profile.setType(type);
                profile.setConf(
                        buildFileOrValue(conf, "ca-conf/certprofile-" + name));

                profiles.getProfile().add(profile);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setProfiles(profiles);
        System.out.println(" exported table PROFILE");
    } // method export_profile

    private void export_ca(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table CA");
        Cas cas = new Cas();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT NAME, ");
        sqlBuilder.append("NEXT_SN, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY, ");
        sqlBuilder.append("CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, ");
        sqlBuilder.append("PERMISSIONS, NUM_CRLS, ");
        sqlBuilder.append("EXPIRATION_PERIOD, KEEP_EXPIRED_CERT_DAYS, REV, RR, RT, RIT, ");
        sqlBuilder.append("DUPLICATE_KEY, DUPLICATE_SUBJECT, DELTACRL_URIS, ");
        sqlBuilder.append("VALIDITY_MODE,CACERT_URIS, ART, NEXT_CRLNO, RESPONDER_NAME, ");
        sqlBuilder.append("CMPCONTROL_NAME, EXTRA_CONTROL");
        sqlBuilder.append(" FROM CA");

        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                int art = rs.getInt("ART");
                int next_crlNo = rs.getInt("NEXT_CRLNO");
                String responder_name = rs.getString("RESPONDER_NAME");
                String cmpcontrol_name = rs.getString("CMPCONTROL_NAME");
                String caCertUris = rs.getString("CACERT_URIS");
                String extraControl = rs.getString("EXTRA_CONTROL");
                long next_serial = rs.getLong("NEXT_SN");
                String status = rs.getString("STATUS");
                String crl_uris = rs.getString("CRL_URIS");
                String delta_crl_uris = rs.getString("DELTACRL_URIS");
                String ocsp_uris = rs.getString("OCSP_URIS");
                String max_validity = rs.getString("MAX_VALIDITY");
                String cert = rs.getString("CERT");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String crlsigner_name = rs.getString("CRLSIGNER_NAME");
                int duplicateKey = rs.getInt("DUPLICATE_KEY");
                int duplicateSubject = rs.getInt("DUPLICATE_SUBJECT");
                String permissions = rs.getString("PERMISSIONS");
                int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");
                int keepExpiredCertDays = rs.getInt("KEEP_EXPIRED_CERT_DAYS");
                String validityMode = rs.getString("VALIDITY_MODE");

                CaType ca = new CaType();
                ca.setName(name);
                ca.setArt(art);
                ca.setNextSerial(next_serial);
                ca.setNextCrlNo(next_crlNo);
                ca.setStatus(status);
                ca.setCrlUris(crl_uris);
                ca.setDeltacrlUris(delta_crl_uris);
                ca.setOcspUris(ocsp_uris);
                ca.setCacertUris(caCertUris);
                ca.setMaxValidity(max_validity);
                ca.setCert(
                        buildFileOrValue(cert, "ca-conf/cert-ca-" + name));
                ca.setSignerType(signer_type);
                ca.setSignerConf(
                        buildFileOrValue(signer_conf, "ca-conf/signerconf-ca-" + name));
                ca.setCrlsignerName(crlsigner_name);
                ca.setResponderName(responder_name);
                ca.setCmpcontrolName(cmpcontrol_name);
                ca.setDuplicateKey(duplicateKey);
                ca.setDuplicateSubject(duplicateSubject);
                ca.setPermissions(permissions);
                ca.setExpirationPeriod(expirationPeriod);
                ca.setKeepExpiredCertDays(keepExpiredCertDays);
                ca.setValidityMode(validityMode);
                ca.setExtraControl(extraControl);

                int numCrls = rs.getInt("NUM_CRLS");
                ca.setNumCrls(numCrls);

                boolean revoked = rs.getBoolean("REV");
                ca.setRevoked(revoked);
                if (revoked) {
                    int reason = rs.getInt("RR");
                    long rev_time = rs.getLong("RT");
                    long rev_invalidity_time = rs.getLong("RIT");
                    ca.setRevReason(reason);
                    ca.setRevTime(rev_time);
                    ca.setRevInvTime(rev_invalidity_time);
                }

                cas.getCa().add(ca);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCas(cas);
        System.out.println(" exported table CA");
    } // method export_ca

    private void export_ca_has_requestor(
            final CAConfigurationType caconf)
    throws DataAccessException {
        System.out.println("exporting table CA_HAS_REQUESTOR");
        CaHasRequestors ca_has_requestors = new CaHasRequestors();
        final String sql = "SELECT CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES"
                + " FROM CA_HAS_REQUESTOR";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
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
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasRequestors(ca_has_requestors);
        System.out.println(" exported table CA_HAS_REQUESTOR");
    } // method export_ca_has_requestor

    private void export_ca_has_publisher(
            final CAConfigurationType caconf)
    throws DataAccessException {
        System.out.println("exporting table CA_HAS_PUBLISHER");
        CaHasPublishers ca_has_publishers = new CaHasPublishers();
        final String sql = "SELECT CA_NAME, PUBLISHER_NAME FROM CA_HAS_PUBLISHER";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String ca_name = rs.getString("CA_NAME");
                String publisher_name = rs.getString("PUBLISHER_NAME");

                CaHasPublisherType ca_has_publisher = new CaHasPublisherType();
                ca_has_publisher.setCaName(ca_name);
                ca_has_publisher.setPublisherName(publisher_name);

                ca_has_publishers.getCaHasPublisher().add(ca_has_publisher);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasPublishers(ca_has_publishers);
        System.out.println(" exported table CA_HAS_PUBLISHER");
    } // method export_ca_has_publisher

    private void export_scep(
            final CAConfigurationType caconf)
    throws DataAccessException, IOException {
        System.out.println("exporting table SCEP");
        Sceps sceps = new Sceps();
        caconf.setSceps(sceps);

        final String sql = "SELECT CA_NAME, RESPONDER_TYPE, RESPONDER_CONF, RESPONDER_CERT,"
                + " CONTROL FROM SCEP";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String ca_name = rs.getString("CA_NAME");
                String resp_type = rs.getString("RESPONDER_TYPE");
                String resp_conf = rs.getString("RESPONDER_CONF");
                String resp_cert = rs.getString("RESPONDER_CERT");
                String control = rs.getString("CONTROL");

                ScepType scep = new ScepType();
                scep.setCaName(ca_name);
                scep.setResponderType(resp_type);
                scep.setResponderConf(
                        buildFileOrValue(resp_conf, "ca-conf/responderconf-scep-" + ca_name));
                scep.setResponderCert(
                        buildFileOrValue(resp_cert, "ca-conf/respondercert-scep-" + ca_name));
                scep.setControl(control);
                sceps.getScep().add(scep);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table SCEP");
    } // method export_scep

    private void export_ca_has_profile(
            final CAConfigurationType caconf)
    throws DataAccessException {
        System.out.println("exporting table CA_HAS_PROFILE");
        CaHasProfiles ca_has_profiles = new CaHasProfiles();
        StringBuilder sqlBuilder = new StringBuilder(100);
        sqlBuilder.append("SELECT CA_NAME, PROFILE_NAME, PROFILE_LOCALNAME FROM CA_HAS_PROFILE");
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String ca_name = rs.getString("CA_NAME");
                String profile_name = rs.getString("PROFILE_NAME");
                String profile_localname = rs.getString("PROFILE_LOCALNAME");

                CaHasProfileType ca_has_profile = new CaHasProfileType();
                ca_has_profile.setCaName(ca_name);
                ca_has_profile.setProfileName(profile_name);
                ca_has_profile.setProfileLocalname(profile_localname);

                ca_has_profiles.getCaHasProfile().add(ca_has_profile);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        caconf.setCaHasProfiles(ca_has_profiles);
        System.out.println(" exported table CA_HAS_PROFILE");
    } // method export_ca_has_profile

}
