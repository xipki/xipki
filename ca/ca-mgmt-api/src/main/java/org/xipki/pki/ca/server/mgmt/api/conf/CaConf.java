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

package org.xipki.pki.ca.server.mgmt.api.conf;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CAConfType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CmpcontrolType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CrlsignerType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ObjectFactory;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ResponderType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.StringsType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.X509CaInfoType;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.2
 */

public class CaConf {

    private final Map<String, String> properties = new HashMap<>();

    private final Map<String, CmpControlEntry> cmpControls = new HashMap<>();

    private final Map<String, CmpResponderEntry> responders = new HashMap<>();

    private final Map<String, String> environments = new HashMap<>();

    private final Map<String, X509CrlSignerEntry> crlSigners = new HashMap<>();

    private final Map<String, CmpRequestorEntry> requestors = new HashMap<>();

    private final Map<String, PublisherEntry> publishers = new HashMap<>();

    private final Map<String, CertprofileEntry> certprofiles = new HashMap<>();

    private final Map<String, SingleCaConf> cas = new HashMap<>();

    private final Map<String, ScepEntry> sceps = new HashMap<>();

    public CaConf(final String confFilename)
    throws IOException, InvalidConfException, CaMgmtException, JAXBException, SAXException {
        try {
            JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();

            final SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = CaConf.class.getResource("/xsd/caconf.xsd");
            jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

            File confFile = new File(confFilename);
            CAConfType root = (CAConfType) ((JAXBElement<?>) jaxbUnmarshaller.unmarshal(confFile))
                    .getValue();
            init(root, confFile.getParentFile().getPath());
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }
    }

    public CaConf(final CAConfType jaxb, final String baseDir)
    throws IOException, InvalidConfException, CaMgmtException {
        ParamUtil.requireNonNull("jaxb", jaxb);
        properties.put("conffile.dir", ParamUtil.requireNonBlank("baseDir", baseDir));
        init(jaxb, baseDir);
    }

    private void init(final CAConfType jaxb, final String baseDir)
    throws IOException, InvalidConfException, CaMgmtException {
        // Properties
        properties.put("baseDir", baseDir);
        if (jaxb.getProperties() != null) {
            for (NameValueType m : jaxb.getProperties().getProperty()) {
                String name = m.getName();
                if (properties.containsKey(name)) {
                    throw new InvalidConfException("Property " + name + " already defined");
                }
                properties.put(name, m.getValue());
            }
        }

        // CMP controls
        if (jaxb.getCmpcontrols() != null) {
            for (CmpcontrolType m : jaxb.getCmpcontrols().getCmpcontrol()) {
                CmpControlEntry en = new CmpControlEntry(m.getName(), getValue(m.getConf()));
                addCmpControl(en);
            }
        }

        // Responders
        if (jaxb.getResponders() != null) {
            for ( ResponderType m : jaxb.getResponders().getResponder()) {
                CmpResponderEntry en = new CmpResponderEntry(m.getName(), extendConf(m.getType()),
                        getValue(m.getConf()), getBase64Binary(m.getCert()));
                addResponder(en);
            }
        }

        // Environments
        if (jaxb.getEnvironments() != null) {
            for (NameValueType m : jaxb.getEnvironments().getEnvironment()) {
                addEnvironment(m.getName(), extendConf(m.getValue()));
            }
        }

        // CRL signers
        if (jaxb.getCrlsigners() != null) {
            for (CrlsignerType m : jaxb.getCrlsigners().getCrlsigner()) {
                X509CrlSignerEntry en = new X509CrlSignerEntry(m.getName(),
                        extendConf(m.getSignerType()), getValue(m.getSignerConf()),
                        getBase64Binary(m.getSignerCert()), extendConf(m.getCrlControl()));
                addCrlSigner(en);
            }
        }

        // Requesters
        if (jaxb.getRequestors() != null) {
            for (RequestorType m : jaxb.getRequestors().getRequestor()) {
                CmpRequestorEntry en = new CmpRequestorEntry(m.getName(),
                        getBase64Binary(m.getCert()));
                addRequestor(en);
            }
        }

        // Publishers
        if (jaxb.getPublishers() != null) {
            for (PublisherType m : jaxb.getPublishers().getPublisher()) {
                PublisherEntry en = new PublisherEntry(m.getName(), extendConf(m.getType()),
                        getValue(m.getConf()));
                addPublisher(en);
            }
        }

        // CertProfiles
        if (jaxb.getProfiles() != null) {
            for (ProfileType m : jaxb.getProfiles().getProfile()) {
                CertprofileEntry en = new CertprofileEntry(m.getName(), extendConf(m.getType()),
                        getValue(m.getConf()));
                addProfile(en);
            }
        }
        // TODO: all enums: getInstance: throws Excpetion if unknown. Never returns null

        // CAs
        if (jaxb.getCas() != null) {
            for (CaType m : jaxb.getCas().getCa()) {
                // TODO: check the completeness of map from JAXB to Java class: cert, ...
                String name = m.getName();
                GenSelfIssued genSelfIssued = null;
                X509CaEntry caEntry = null;

                if (m.getCaInfo() != null) {
                    X509CaInfoType ci = m.getCaInfo().getX509Ca();
                    if (ci.getGenSelfIssued() != null) {
                        String certFilename = null;
                        if (ci.getCert() != null) {
                            if (ci.getCert().getFile() != null) {
                                certFilename = extendConf(ci.getCert().getFile());
                            } else {
                                throw new InvalidConfException("cert.file of CA " + name
                                        + " must not be null");
                            }
                        }
                        genSelfIssued = new GenSelfIssued(ci.getGenSelfIssued().getProfile(),
                                getBinary(ci.getGenSelfIssued().getCsr()), certFilename);
                    }

                    X509CaUris caUris = new X509CaUris(getStrings(ci.getCacertUris()),
                            getStrings(ci.getOcspUris()), getStrings(ci.getCrlUris()),
                            getStrings(ci.getDeltacrlUris()));

                    int exprirationPeriod = (ci.getExpirationPeriod() == null) ? 365
                            : ci.getExpirationPeriod().intValue();

                    int numCrls = (ci.getNumCrls() == null) ? 30 : ci.getNumCrls().intValue();

                    caEntry = new X509CaEntry(name, ci.getSnSize(), ci.getNextCrlNo(),
                            extendConf(ci.getSignerType()), getValue(ci.getSignerConf()),
                            caUris, numCrls, exprirationPeriod);

                    caEntry.setCmpControlName(ci.getCmpcontrolName());
                    caEntry.setCrlSignerName(ci.getCrlsignerName());
                    caEntry.setDuplicateKeyPermitted(ci.isDuplicateKey());
                    caEntry.setDuplicateSubjectPermitted(ci.isDuplicateSubject());

                    if (ci.getExtraControl() != null) {
                        caEntry.setExtraControl(getValue(ci.getExtraControl()));
                    }

                    int keepExpiredCertDays = (ci.getKeepExpiredCertDays() == null) ? -1
                            : ci.getKeepExpiredCertDays().intValue();
                    caEntry.setKeepExpiredCertInDays(keepExpiredCertDays);

                    caEntry.setMaxValidity(CertValidity.getInstance(ci.getMaxValidity()));
                    List<String> permStrs = getStrings(ci.getPermissions());
                    if (permStrs != null) {
                        Set<Permission> permissions = new HashSet<>();
                        for (String per : permStrs) {
                            permissions.add(Permission.forValue(per));
                        }
                        caEntry.setPermissions(permissions);
                    }

                    caEntry.setResponderName(ci.getResponderName());

                    caEntry.setSaveRequest(ci.isSaveReq());
                    caEntry.setStatus(CaStatus.forName(ci.getStatus()));

                    if (ci.getValidityMode() != null) {
                        caEntry.setValidityMode(ValidityMode.forName(ci.getValidityMode()));
                    }

                    if (ci.getGenSelfIssued() == null && ci.getCert() != null) {
                        byte[] bytes = getBinary(ci.getCert());
                        try {
                            caEntry.setCertificate(X509Util.parseCert(bytes));
                        } catch (CertificateException ex) {
                            throw new InvalidConfException("invalid certificate of CA " + name, ex);
                        }
                    }
                }

                List<CaHasRequestorEntry> caHasRequestors = null;
                if (m.getRequestors() != null) {
                    caHasRequestors = new LinkedList<>();
                    for (CaHasRequestorType req : m.getRequestors().getRequestor()) {
                        CaHasRequestorEntry en = new CaHasRequestorEntry(req.getRequestorName());
                        en.setRa(req.isRa());

                        List<String> strs = getStrings(req.getProfiles());
                        if (strs != null) {
                            en.setProfiles(new HashSet<>(strs));
                        }

                        strs = getStrings(req.getPermissions());
                        if (strs != null) {
                            Set<Permission> permissions = new HashSet<>();
                            for (String perm : strs) {
                                permissions.add(Permission.forValue(perm));
                            }

                            en.setPermissions(permissions);
                        }
                        caHasRequestors.add(en);
                    }
                }

                List<String> profileNames = getStrings(m.getProfiles());
                List<String> publisherNames = getStrings(m.getPublishers());

                SingleCaConf singleCa = new SingleCaConf(name, genSelfIssued, caEntry,
                        extendConf(m.getAlias()), profileNames, caHasRequestors, publisherNames);
                addSingleCa(singleCa);
            }
        }
    }

    public void addCmpControl(final CmpControlEntry cmpControl) {
        ParamUtil.requireNonNull("cmpControl", cmpControl);
        this.cmpControls.put(cmpControl.getName(), cmpControl);
    }

    public Set<String> getCmpControlNames() {
        return Collections.unmodifiableSet(cmpControls.keySet());
    }

    public CmpControlEntry getCmpControl(final String name) {
        return cmpControls.get(ParamUtil.requireNonNull("name", name));
    }

    public void addResponder(final CmpResponderEntry responder) {
        ParamUtil.requireNonNull("responder", responder);
        this.responders.put(responder.getName(), responder);
    }

    public Set<String> getResponderNames() {
        return Collections.unmodifiableSet(responders.keySet());
    }

    public CmpResponderEntry getResponder(final String name) {
        return responders.get(ParamUtil.requireNonNull("name", name));
    }

    public void addEnvironment(final String name, final String value) {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonBlank("value", value);
        this.environments.put(name, value);
    }

    public Set<String> getEnvironmentNames() {
        return Collections.unmodifiableSet(environments.keySet());
    }

    public String getEnvironment(final String name) {
        return environments.get(ParamUtil.requireNonNull("name", name));
    }

    public void addCrlSigner(final X509CrlSignerEntry crlSigner) {
        ParamUtil.requireNonNull("crlSigner", crlSigner);
        this.crlSigners.put(crlSigner.getName(), crlSigner);
    }

    public Set<String> getCrlSignerNames() {
        return Collections.unmodifiableSet(crlSigners.keySet());
    }

    public X509CrlSignerEntry getCrlSigner(final String name) {
        return crlSigners.get(ParamUtil.requireNonNull("name", name));
    }

    public void addRequestor(final CmpRequestorEntry requestor) {
        ParamUtil.requireNonNull("requestor", requestor);
        this.requestors.put(requestor.getName(), requestor);
    }

    public Set<String> getRequestorNames() {
        return Collections.unmodifiableSet(requestors.keySet());
    }

    public CmpRequestorEntry getRequestor(final String name) {
        return requestors.get(ParamUtil.requireNonNull("name", name));
    }

    public void addPublisher(final PublisherEntry publisher) {
        ParamUtil.requireNonNull("publisher", publisher);
        this.publishers.put(publisher.getName(), publisher);
    }

    public Set<String> getPublisherNames() {
        return Collections.unmodifiableSet(publishers.keySet());
    }

    public PublisherEntry getPublisher(final String name) {
        return publishers.get(ParamUtil.requireNonNull("name", name));
    }

    public void addProfile(final CertprofileEntry profile) {
        ParamUtil.requireNonNull("profile", profile);
        this.certprofiles.put(profile.getName(), profile);
    }

    public Set<String> getCertProfileNames() {
        return Collections.unmodifiableSet(certprofiles.keySet());
    }

    public CertprofileEntry getCertProfile(final String name) {
        return certprofiles.get(ParamUtil.requireNonNull("name", name));
    }

    public void addSingleCa(final SingleCaConf singleCa) {
        ParamUtil.requireNonNull("singleCa", singleCa);
        this.cas.put(singleCa.getName(), singleCa);
    }

    public Set<String> getCaNames() {
        return Collections.unmodifiableSet(cas.keySet());
    }

    public SingleCaConf getCa(final String name) {
        return cas.get(ParamUtil.requireNonNull("name", name));
    }

    public void addScep(final ScepEntry scep) {
        ParamUtil.requireNonNull("scep", scep);
        this.sceps.put(scep.getCaName(), scep);
    }

    public Set<String> getScepNames() {
        return Collections.unmodifiableSet(sceps.keySet());
    }

    public ScepEntry getScep(final String name) {
        return sceps.get(ParamUtil.requireNonNull("name", name));
    }

    private String getValue(final FileOrValueType fileOrValue) throws IOException {
        if (fileOrValue == null) {
            return null;
        }

        if (fileOrValue.getValue() != null) {
            return extendConf(fileOrValue.getValue());
        }

        File file = new File(extendConf(fileOrValue.getFile()));
        return extendConf(new String(IoUtil.read(file), "UTF-8"));
    }

    private String getBase64Binary(final FileOrBinaryType fileOrBinary) throws IOException {
        byte[] binary = getBinary(fileOrBinary);
        return (binary == null) ? null : Base64.toBase64String(binary);
    }

    private byte[] getBinary(final FileOrBinaryType fileOrBinary) throws IOException {
        if (fileOrBinary == null) {
            return null;
        }

        if (fileOrBinary.getBinary() != null) {
            return fileOrBinary.getBinary();
        }

        File file = new File(extendConf(fileOrBinary.getFile()));
        return IoUtil.read(file);
    }

    private List<String> getStrings(StringsType jaxb) {
        if (jaxb == null) {
            return null;
        }

        List<String> ret = new ArrayList<>(jaxb.getStr().size());
        for (String m : jaxb.getStr()) {
            ret.add(extendConf(m));
        }
        return ret;
    }

    private final String extendConf(String confStr) {
        if (confStr == null || !confStr.contains("${") || confStr.indexOf('}') == -1) {
            return confStr;
        }

        for (String name : properties.keySet()) {
            String placeHolder = "${" + name + "}";
            while (confStr.contains(placeHolder)) {
                confStr = confStr.replace(placeHolder, properties.get(name));
            }
        }

        return confStr;
    }
}
