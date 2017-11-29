/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.dbtool.port.ca;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasProfiles;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasPublishers;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.CaHasRequestors;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Caaliases;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Cas;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Cmpcontrols;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Crlsigners;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Environments;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Profiles;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Publishers;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Requestors;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Responders;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType.Sceps;
import org.xipki.ca.dbtool.jaxb.ca.CaHasProfileType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasPublisherType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasRequestorType;
import org.xipki.ca.dbtool.jaxb.ca.CaType;
import org.xipki.ca.dbtool.jaxb.ca.CaaliasType;
import org.xipki.ca.dbtool.jaxb.ca.CmpcontrolType;
import org.xipki.ca.dbtool.jaxb.ca.CrlsignerType;
import org.xipki.ca.dbtool.jaxb.ca.EnvironmentType;
import org.xipki.ca.dbtool.jaxb.ca.ProfileType;
import org.xipki.ca.dbtool.jaxb.ca.PublisherType;
import org.xipki.ca.dbtool.jaxb.ca.RequestorType;
import org.xipki.ca.dbtool.jaxb.ca.ResponderType;
import org.xipki.ca.dbtool.jaxb.ca.ScepType;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaConfigurationDbImporter extends DbPorter {

    private final Unmarshaller unmarshaller;

    CaConfigurationDbImporter(final DataSourceWrapper datasource, final Unmarshaller unmarshaller,
            final String srcDir, final AtomicBoolean stopMe, final boolean evaluateOnly)
            throws DataAccessException, PasswordResolverException, IOException {
        super(datasource, srcDir, stopMe, evaluateOnly);
        this.unmarshaller = ParamUtil.requireNonNull("unmarshaller", unmarshaller);
    }

    public void importToDb() throws Exception {
        CAConfigurationType caconf;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CAConfigurationType> root = (JAXBElement<CAConfigurationType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CONFIGURATION));
            caconf = root.getValue();
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }

        if (caconf.getVersion() > VERSION) {
            throw new InvalidInputException("could not import CA configuration greater than "
                    + VERSION + ": " + caconf.getVersion());
        }

        System.out.println("importing CA configuration to database");
        try {
            importCmpcontrol(caconf.getCmpcontrols());
            importResponder(caconf.getResponders());
            importEnvironment(caconf.getEnvironments());
            importRequestor(caconf.getRequestors());
            importPublisher(caconf.getPublishers());
            importProfile(caconf.getProfiles());
            importCrlsigner(caconf.getCrlsigners());
            importCa(caconf.getCas());
            importCaalias(caconf.getCaaliases());
            importCaHasRequestor(caconf.getCaHasRequestors());
            importCaHasPublisher(caconf.getCaHasPublishers());
            importCaHasCertprofile(caconf.getCaHasProfiles());
            importScep(caconf.getSceps());
        } catch (Exception ex) {
            System.err.println("could not import CA configuration to database. message: "
                    + ex.getMessage());
            throw ex;
        }
        System.out.println(" imported CA configuration to database");
    } // method importToDb

    private void importCmpcontrol(final Cmpcontrols controls) throws DataAccessException {
        System.out.println("importing table CMPCONTROL");
        final String sql = "INSERT INTO CMPCONTROL (NAME,CONF) VALUES (?,?)";

        if (controls != null && CollectionUtil.isNonEmpty(controls.getCmpcontrol())) {
            PreparedStatement ps = null;
            try {
                ps = prepareStatement(sql);

                for (CmpcontrolType control : controls.getCmpcontrol()) {
                    try {
                        int idx = 1;
                        ps.setString(idx++, control.getName());
                        ps.setString(idx++, control.getConf());

                        ps.executeUpdate();
                    } catch (SQLException ex) {
                        System.err.println("could not import CMPCONTROL " + control.getName());
                        throw translate(sql, ex);
                    }
                }
            } finally {
                releaseResources(ps, null);
            }
        }
        System.out.println(" imported table CMPCONTROL");
    } // method importCmpcontrol

    private void importResponder(final Responders responders)
            throws DataAccessException, IOException {
        System.out.println("importing table RESPONDER");
        if (responders == null) {
            System.out.println(" imported table RESPONDER: nothing to import");
            return;
        }
        final String sql = "INSERT INTO RESPONDER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            for (ResponderType responder : responders.getResponder()) {
                byte[] certBytes = binary(responder.getCert());
                String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
                try {
                    int idx = 1;
                    ps.setString(idx++, responder.getName());
                    ps.setString(idx++, responder.getType());
                    ps.setString(idx++, b64Cert);
                    ps.setString(idx++, value(responder.getConf()));

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CRLSIGNER with NAME="
                            + responder.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table RESPONDER");
    } // method importResponder

    private void importEnvironment(final Environments environments) throws DataAccessException {
        System.out.println("importing table ENVIRONMENT");
        final String sql = "INSERT INTO ENVIRONMENT (NAME,VALUE2) VALUES (?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            for (EnvironmentType environment : environments.getEnvironment()) {
                try {
                    int idx = 1;
                    ps.setString(idx++, environment.getName());
                    ps.setString(idx++, environment.getValue());
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import ENVIRONMENT with NAME="
                            + environment.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table ENVIRONMENT");
    } // method importEnvironment

    private void importCrlsigner(final Crlsigners crlsigners)
            throws DataAccessException, IOException {
        System.out.println("importing table CRLSIGNER");
        final String sql = "INSERT INTO CRLSIGNER (NAME,SIGNER_TYPE,SIGNER_CERT,CRL_CONTROL,"
                + "SIGNER_CONF) VALUES (?,?,?,?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            for (CrlsignerType crlsigner : crlsigners.getCrlsigner()) {
                byte[] certBytes = binary(crlsigner.getSignerCert());
                String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
                try {
                    int idx = 1;
                    ps.setString(idx++, crlsigner.getName());
                    ps.setString(idx++, crlsigner.getSignerType());
                    ps.setString(idx++, b64Cert);
                    ps.setString(idx++, crlsigner.getCrlControl());
                    ps.setString(idx++, value(crlsigner.getSignerConf()));
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CRLSIGNER with NAME="
                            + crlsigner.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CRLSIGNER");
    } // method importCrlsigner

    private void importRequestor(final Requestors requestors)
            throws DataAccessException, IOException {
        System.out.println("importing table REQUESTOR");
        final String sql = "INSERT INTO REQUESTOR (ID,NAME,CERT) VALUES (?,?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            for (RequestorType requestor : requestors.getRequestor()) {
                byte[] certBytes = binary(requestor.getCert());
                String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
                try {
                    int idx = 1;
                    ps.setInt(idx++, requestor.getId());
                    ps.setString(idx++, requestor.getName());
                    ps.setString(idx++, b64Cert);

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import REQUESTOR with NAME="
                            + requestor.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table REQUESTOR");
    } // method importRequestor

    private void importPublisher(final Publishers publishers)
            throws DataAccessException, IOException {
        System.out.println("importing table PUBLISHER");
        final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            for (PublisherType publisher : publishers.getPublisher()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, publisher.getId());
                    ps.setString(idx++, publisher.getName());
                    ps.setString(idx++, publisher.getType());
                    ps.setString(idx++, value(publisher.getConf()));

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import PUBLISHER with NAME="
                            + publisher.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table PUBLISHER");
    } // method importPublisher

    private void importProfile(final Profiles profiles) throws DataAccessException, IOException {
        System.out.println("importing table PROFILE");
        final String sql = "INSERT INTO PROFILE (ID,NAME,ART,TYPE,CONF) VALUES (?,?,?,?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            for (ProfileType certprofile : profiles.getProfile()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, certprofile.getId());
                    ps.setString(idx++, certprofile.getName());
                    int art = (certprofile.getArt() == null) ? 1 : certprofile.getArt();
                    ps.setInt(idx++, art);
                    ps.setString(idx++, certprofile.getType());

                    String conf = value(certprofile.getConf());
                    ps.setString(idx++, conf);

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import PROFILE with NAME="
                            + certprofile.getName());
                    throw translate(sql, ex);
                } catch (IOException ex) {
                    System.err.println("could not import PROFILE with NAME="
                            + certprofile.getName());
                    throw ex;
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table PROFILE");
    } // method importProfile

    private void importCa(final Cas cas)
            throws DataAccessException, CertificateException, IOException {
        System.out.println("importing table CA");
        StringBuilder sqlBuilder = new StringBuilder(500);
        sqlBuilder.append("INSERT INTO CA (ID,NAME,ART,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,");
        sqlBuilder.append("CRL_URIS,DELTACRL_URIS,OCSP_URIS,CACERT_URIS,MAX_VALIDITY,");
        sqlBuilder.append("CERT,SIGNER_TYPE,CRLSIGNER_NAME,RESPONDER_NAME,CMPCONTROL_NAME,");
        sqlBuilder.append("DUPLICATE_KEY,DUPLICATE_SUBJECT,SAVE_REQ,PERMISSION,");
        sqlBuilder.append("NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,");
        sqlBuilder.append("REV,RR,RT,RIT,VALIDITY_MODE,EXTRA_CONTROL,SIGNER_CONF)");
        sqlBuilder.append(" VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            for (CaType ca : cas.getCa()) {
                int art = (ca.getArt() == null) ? 1 : ca.getArt();

                try {
                    byte[] certBytes = binary(ca.getCert());
                    X509Certificate cert = X509Util.parseCert(certBytes);

                    int idx = 1;
                    ps.setInt(idx++, ca.getId());
                    ps.setString(idx++, ca.getName().toUpperCase());
                    ps.setInt(idx++, art);
                    ps.setString(idx++, X509Util.cutX500Name(cert.getSubjectX500Principal(),
                            maxX500nameLen));
                    ps.setInt(idx++, ca.getSnSize());
                    ps.setLong(idx++, ca.getNextCrlNo());
                    ps.setString(idx++, ca.getStatus());
                    ps.setString(idx++, ca.getCrlUris());
                    ps.setString(idx++, ca.getDeltacrlUris());
                    ps.setString(idx++, ca.getOcspUris());
                    ps.setString(idx++, ca.getCacertUris());
                    ps.setString(idx++, ca.getMaxValidity());
                    ps.setString(idx++, Base64.encodeToString(certBytes));
                    ps.setString(idx++, ca.getSignerType());
                    ps.setString(idx++, ca.getCrlsignerName());
                    ps.setString(idx++, ca.getResponderName());
                    ps.setString(idx++, ca.getCmpcontrolName());
                    ps.setInt(idx++, ca.getDuplicateKey());
                    ps.setInt(idx++, ca.getDuplicateSubject());
                    ps.setInt(idx++, ca.getSaveReq());
                    ps.setInt(idx++, ca.getPermission());
                    Integer numCrls = ca.getNumCrls();
                    int tmpNumCrls = (numCrls == null) ? 30 : numCrls.intValue();
                    ps.setInt(idx++, tmpNumCrls);
                    ps.setInt(idx++, ca.getExpirationPeriod());
                    ps.setInt(idx++, ca.getKeepExpiredCertDays());
                    setBoolean(ps, idx++, ca.isRevoked());
                    setInt(ps, idx++, ca.getRevReason());
                    setLong(ps, idx++, ca.getRevTime());
                    setLong(ps, idx++, ca.getRevInvTime());
                    ps.setString(idx++, ca.getValidityMode());
                    ps.setString(idx++, ca.getExtraControl());
                    ps.setString(idx++, value(ca.getSignerConf()));

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CA with NAME=" + ca.getName());
                    throw translate(sql, ex);
                } catch (CertificateException | IOException ex) {
                    System.err.println("could not import CA with NAME=" + ca.getName());
                    throw ex;
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CA");
    } // method importCa

    private void importCaalias(final Caaliases caaliases) throws DataAccessException {
        System.out.println("importing table CAALIAS");
        final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
        PreparedStatement ps = prepareStatement(sql);
        try {
            for (CaaliasType caalias : caaliases.getCaalias()) {
                try {
                    int idx = 1;
                    ps.setString(idx++, caalias.getName());
                    ps.setInt(idx++, caalias.getCaId());
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CAALIAS with NAME=" + caalias.getName());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CAALIAS");
    } // method importCaalias

    private void importCaHasRequestor(final CaHasRequestors caHasRequestors)
            throws DataAccessException {
        System.out.println("importing table CA_HAS_REQUESTOR");
        final String sql =
                "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA,PERMISSION,PROFILES)"
                + " VALUES (?,?,?,?,?)";
        PreparedStatement ps = prepareStatement(sql);
        try {
            for (CaHasRequestorType entry : caHasRequestors.getCaHasRequestor()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, entry.getCaId());
                    ps.setInt(idx++, entry.getRequestorId());
                    setBoolean(ps, idx++, entry.isRa());
                    ps.setInt(idx++, entry.getPermission());
                    ps.setString(idx++, entry.getProfiles());

                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CA_HAS_REQUESTOR with CA_ID="
                        + entry.getCaId() + " and REQUESTOR_ID=" + entry.getRequestorId());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_REQUESTOR");
    } // method importCaHasRequestor

    private void importCaHasPublisher(final CaHasPublishers caHasPublishers) throws Exception {
        System.out.println("importing table CA_HAS_PUBLISHER");
        final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
        PreparedStatement ps = prepareStatement(sql);
        try {
            for (CaHasPublisherType entry : caHasPublishers.getCaHasPublisher()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, entry.getCaId());
                    ps.setInt(idx++, entry.getPublisherId());
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CA_HAS_PUBLISHER with CA_ID="
                        + entry.getCaId() + " and PUBLISHER_ID=" + entry.getPublisherId());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_PUBLISHER");
    } // method importCaHasPublisher

    private void importCaHasCertprofile(final CaHasProfiles caHasCertprofiles)
            throws DataAccessException {
        System.out.println("importing table CA_HAS_PROFILE");
        final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
        PreparedStatement ps = prepareStatement(sql);
        try {
            for (CaHasProfileType entry : caHasCertprofiles.getCaHasProfile()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, entry.getCaId());
                    ps.setInt(idx++, entry.getProfileId());
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import CA_HAS_PROFILE with CA_ID="
                            + entry.getCaId() + " and PROFILE_ID=" + entry.getProfileId());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table CA_HAS_PROFILE");
    } // method importCaHasCertprofile

    private void importScep(final Sceps sceps) throws DataAccessException, IOException {
        System.out.println("importing table SCEP");
        final String sql = "INSERT INTO SCEP (NAME,CA_ID,ACTIVE,PROFILES,RESPONDER_TYPE,"
                + "RESPONDER_CERT,CONTROL,RESPONDER_CONF) VALUES (?,?,?,?,?,?,?,?)";
        PreparedStatement ps = prepareStatement(sql);
        try {
            for (ScepType entry : sceps.getScep()) {
                byte[] certBytes = binary(entry.getResponderCert());
                String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
                try {
                    int idx = 1;
                    ps.setString(idx++, entry.getName());
                    ps.setInt(idx++, entry.getCaId());
                    ps.setInt(idx++, entry.getActive());
                    ps.setString(idx++, entry.getProfiles());
                    ps.setString(idx++, entry.getResponderType());
                    ps.setString(idx++, b64Cert);
                    ps.setString(idx++, entry.getControl());
                    ps.setString(idx++, value(entry.getResponderConf()));
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    System.err.println("could not import SCEP with ID=" + entry.getCaId());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table SCEP");
    } // method importScep

}
