/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt.api.conf;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CAConfType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CmpcontrolType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CrlsignerType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ObjectFactory;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ResponderType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ScepType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.StringsType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.X509CaInfoType;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaConf {
    private static final Logger LOG = LoggerFactory.getLogger(CaConf.class);

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

    public CaConf(String confFilename, SecurityFactory securityFactory)
            throws IOException, InvalidConfException, CaMgmtException, JAXBException, SAXException {
        ParamUtil.requireNonBlank("confFilename", confFilename);
        ParamUtil.requireNonNull("securityFactory", securityFactory);

        int fileExtIndex = confFilename.lastIndexOf('.');
        String fileExt = null;
        if (fileExtIndex != -1) {
            fileExt = confFilename.substring(fileExtIndex + 1);
        }

        File confFile = new File(confFilename);

        ZipFile zipFile = null;
        InputStream caConfStream = null;

        try {
            if ("xml".equalsIgnoreCase(fileExt)) {
                LOG.info("read the configuration file {} as an XML file", confFilename);
                caConfStream = new FileInputStream(confFile);
            } else if ("zip".equalsIgnoreCase(fileExt)) {
                LOG.info("read the configuration file {} as a ZIP file", confFilename);
                zipFile = new ZipFile(confFile);
                caConfStream = zipFile.getInputStream(zipFile.getEntry("caconf.xml"));
            } else {
                try {
                    LOG.info("try to read the configuration file {} as a ZIP file", confFilename);
                    zipFile = new ZipFile(confFile);
                    caConfStream = zipFile.getInputStream(zipFile.getEntry("caconf.xml"));
                } catch (ZipException ex) {
                    LOG.info("the configuration file {} is not a ZIP file, try as an XML file",
                            confFilename);
                    zipFile = null;
                    caConfStream = new FileInputStream(confFile);
                }
            }

            String baseDir = (zipFile == null) ? null : confFile.getParentFile().getPath();

            JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);

            SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = CaConf.class.getResource("/xsd/caconf.xsd");
            Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();
            jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

            CAConfType root = (CAConfType) ((JAXBElement<?>)
                    jaxbUnmarshaller.unmarshal(caConfStream)).getValue();
            init(root, baseDir, zipFile, securityFactory);
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        } finally {
            if (caConfStream != null) {
                try {
                    caConfStream.close();
                } catch (IOException ex) {
                    LOG.info("could not clonse caConfStream", ex.getMessage());
                }
            }

            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (IOException ex) {
                    LOG.info("could not clonse zipFile", ex.getMessage());
                }
            }
        }
    }

    public static void marshal(CAConfType jaxb, OutputStream out)
            throws JAXBException, SAXException {
        ParamUtil.requireNonNull("jaxb", jaxb);
        ParamUtil.requireNonNull("out", out);

        try {
            JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);

            SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = CaConf.class.getResource("/xsd/caconf.xsd");
            Marshaller jaxbMarshaller = context.createMarshaller();
            jaxbMarshaller.setSchema(schemaFact.newSchema(url));

            jaxbMarshaller.marshal(new ObjectFactory().createCAConf(jaxb), out);
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }
    }

    private void init(CAConfType jaxb, String baseDir, ZipFile zipFile,
            SecurityFactory securityFactory)
            throws IOException, InvalidConfException, CaMgmtException {
        // Properties
        if (baseDir != null) {
            properties.put("baseDir", baseDir);
        }

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
                CmpControlEntry en = new CmpControlEntry(m.getName(),
                        getValue(m.getConf(), zipFile));
                addCmpControl(en);
            }
        }

        // Responders
        if (jaxb.getResponders() != null) {
            for ( ResponderType m : jaxb.getResponders().getResponder()) {
                CmpResponderEntry en = new CmpResponderEntry(m.getName(), expandConf(m.getType()),
                        getValue(m.getConf(), zipFile), getBase64Binary(m.getCert(), zipFile));
                addResponder(en);
            }
        }

        // Environments
        if (jaxb.getEnvironments() != null) {
            for (NameValueType m : jaxb.getEnvironments().getEnvironment()) {
                addEnvironment(m.getName(), expandConf(m.getValue()));
            }
        }

        // CRL signers
        if (jaxb.getCrlsigners() != null) {
            for (CrlsignerType m : jaxb.getCrlsigners().getCrlsigner()) {
                X509CrlSignerEntry en = new X509CrlSignerEntry(m.getName(),
                        expandConf(m.getSignerType()), getValue(m.getSignerConf(), zipFile),
                        getBase64Binary(m.getSignerCert(), zipFile), expandConf(m.getCrlControl()));
                addCrlSigner(en);
            }
        }

        // Requesters
        if (jaxb.getRequestors() != null) {
            for (RequestorType m : jaxb.getRequestors().getRequestor()) {
                CmpRequestorEntry en = new CmpRequestorEntry(new NameId(null, m.getName()),
                        getBase64Binary(m.getCert(), zipFile));
                addRequestor(en);
            }
        }

        // Publishers
        if (jaxb.getPublishers() != null) {
            for (PublisherType m : jaxb.getPublishers().getPublisher()) {
                PublisherEntry en = new PublisherEntry(new NameId(null, m.getName()),
                        expandConf(m.getType()), getValue(m.getConf(), zipFile));
                addPublisher(en);
            }
        }

        // CertProfiles
        if (jaxb.getProfiles() != null) {
            for (ProfileType m : jaxb.getProfiles().getProfile()) {
                CertprofileEntry en = new CertprofileEntry(new NameId(null, m.getName()),
                        expandConf(m.getType()), getValue(m.getConf(), zipFile));
                addProfile(en);
            }
        }

        // CAs
        if (jaxb.getCas() != null) {
            for (CaType m : jaxb.getCas().getCa()) {
                String name = m.getName();
                GenSelfIssued genSelfIssued = null;
                X509CaEntry caEntry = null;

                if (m.getCaInfo() != null) {
                    X509CaInfoType ci = m.getCaInfo().getX509Ca();
                    if (ci.getGenSelfIssued() != null) {
                        String certFilename = null;
                        if (ci.getCert() != null) {
                            if (ci.getCert().getFile() != null) {
                                certFilename = expandConf(ci.getCert().getFile());
                            } else {
                                throw new InvalidConfException("cert.file of CA " + name
                                        + " must not be null");
                            }
                        }
                        byte[] csr = getBinary(ci.getGenSelfIssued().getCsr(), zipFile);
                        BigInteger serialNumber = null;
                        String str = ci.getGenSelfIssued().getSerialNumber();
                        if (str != null) {
                            str = str.toUpperCase();
                            if (str.startsWith("0X")) {
                                serialNumber = new BigInteger(str.substring(2), 16);
                            } else {
                                serialNumber = new BigInteger(str);
                            }
                        }

                        genSelfIssued = new GenSelfIssued(ci.getGenSelfIssued().getProfile(),
                                csr, serialNumber, certFilename);
                    }

                    X509CaUris caUris = new X509CaUris(getStrings(ci.getCacertUris()),
                            getStrings(ci.getOcspUris()), getStrings(ci.getCrlUris()),
                            getStrings(ci.getDeltacrlUris()));

                    int exprirationPeriod = (ci.getExpirationPeriod() == null) ? 365
                            : ci.getExpirationPeriod().intValue();

                    int numCrls = (ci.getNumCrls() == null) ? 30 : ci.getNumCrls().intValue();

                    caEntry = new X509CaEntry(new NameId(null, name), ci.getSnSize(),
                            ci.getNextCrlNo(), expandConf(ci.getSignerType()),
                            getValue(ci.getSignerConf(), zipFile),
                            caUris, numCrls, exprirationPeriod);

                    caEntry.setCmpControlName(ci.getCmpcontrolName());
                    caEntry.setCrlSignerName(ci.getCrlsignerName());
                    caEntry.setDuplicateKeyPermitted(ci.isDuplicateKey());
                    caEntry.setDuplicateSubjectPermitted(ci.isDuplicateSubject());
                    if (ci.getExtraControl() != null) {
                        caEntry.setExtraControl(getValue(ci.getExtraControl(), zipFile));
                    }

                    int keepExpiredCertDays = (ci.getKeepExpiredCertDays() == null) ? -1
                            : ci.getKeepExpiredCertDays().intValue();
                    caEntry.setKeepExpiredCertInDays(keepExpiredCertDays);

                    caEntry.setMaxValidity(CertValidity.getInstance(ci.getMaxValidity()));
                    caEntry.setPermission(ci.getPermission());

                    caEntry.setResponderName(ci.getResponderName());

                    caEntry.setSaveRequest(ci.isSaveReq());
                    caEntry.setStatus(CaStatus.forName(ci.getStatus()));

                    if (ci.getValidityMode() != null) {
                        caEntry.setValidityMode(ValidityMode.forName(ci.getValidityMode()));
                    }

                    if (ci.getGenSelfIssued() == null) {
                        X509Certificate caCert;

                        if (ci.getCert() != null) {
                            byte[] bytes = getBinary(ci.getCert(), zipFile);
                            try {
                                caCert = X509Util.parseCert(bytes);
                            } catch (CertificateException ex) {
                                throw new InvalidConfException("invalid certificate of CA " + name,
                                        ex);
                            }
                        } else {
                            // extract from the signer configuration
                            ConcurrentContentSigner signer;
                            try {
                                List<String[]> signerConfs = CaEntry.splitCaSignerConfs(
                                        getValue(ci.getSignerConf(), zipFile));
                                SignerConf signerConf = new SignerConf(signerConfs.get(0)[1]);

                                signer = securityFactory.createSigner(
                                        expandConf(ci.getSignerType()), signerConf,
                                        (X509Certificate) null);
                            } catch (ObjectCreationException | XiSecurityException ex) {
                                throw new InvalidConfException("could not create CA signer for CA "
                                        + name, ex);
                            }
                            caCert = signer.getCertificate();
                        }

                        caEntry.setCertificate(caCert);
                    }
                }

                List<CaHasRequestorEntry> caHasRequestors = null;
                if (m.getRequestors() != null) {
                    caHasRequestors = new LinkedList<>();
                    for (CaHasRequestorType req : m.getRequestors().getRequestor()) {
                        CaHasRequestorEntry en = new CaHasRequestorEntry(
                                new NameId(null, req.getRequestorName()));
                        en.setRa(req.isRa());

                        List<String> strs = getStrings(req.getProfiles());
                        if (strs != null) {
                            en.setProfiles(new HashSet<>(strs));
                        }

                        en.setPermission(req.getPermission());
                        caHasRequestors.add(en);
                    }
                }

                List<String> aliases = getStrings(m.getAliases());
                List<String> profileNames = getStrings(m.getProfiles());
                List<String> publisherNames = getStrings(m.getPublishers());

                SingleCaConf singleCa = new SingleCaConf(name, genSelfIssued, caEntry, aliases,
                        profileNames, caHasRequestors, publisherNames);
                addSingleCa(singleCa);
            }
        }

        // SCEPs
        if (jaxb.getSceps() != null) {
            for (ScepType m : jaxb.getSceps().getScep()) {
                String name = m.getName();
                NameId caIdent = new NameId(null, m.getCaName());
                String responderConf = getValue(m.getResponderConf(), zipFile);
                List<String> certProfiles = getStrings(m.getProfiles());
                ScepEntry dbEntry = new ScepEntry(name, caIdent, true, m.getResponderType(),
                        responderConf, null, new HashSet<>(certProfiles), m.getControl());
                sceps.put(name, dbEntry);
            }
        }

    }

    public void addCmpControl(CmpControlEntry cmpControl) {
        ParamUtil.requireNonNull("cmpControl", cmpControl);
        this.cmpControls.put(cmpControl.name(), cmpControl);
    }

    public Set<String> getCmpControlNames() {
        return Collections.unmodifiableSet(cmpControls.keySet());
    }

    public CmpControlEntry getCmpControl(String name) {
        return cmpControls.get(ParamUtil.requireNonNull("name", name));
    }

    public void addResponder(CmpResponderEntry responder) {
        ParamUtil.requireNonNull("responder", responder);
        this.responders.put(responder.name(), responder);
    }

    public Set<String> getResponderNames() {
        return Collections.unmodifiableSet(responders.keySet());
    }

    public CmpResponderEntry getResponder(String name) {
        return responders.get(ParamUtil.requireNonNull("name", name));
    }

    public void addEnvironment(String name, String value) {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonBlank("value", value);
        this.environments.put(name, value);
    }

    public Set<String> getEnvironmentNames() {
        return Collections.unmodifiableSet(environments.keySet());
    }

    public String getEnvironment(String name) {
        return environments.get(ParamUtil.requireNonNull("name", name));
    }

    public void addCrlSigner(X509CrlSignerEntry crlSigner) {
        ParamUtil.requireNonNull("crlSigner", crlSigner);
        this.crlSigners.put(crlSigner.name(), crlSigner);
    }

    public Set<String> getCrlSignerNames() {
        return Collections.unmodifiableSet(crlSigners.keySet());
    }

    public X509CrlSignerEntry getCrlSigner(String name) {
        return crlSigners.get(ParamUtil.requireNonNull("name", name));
    }

    public void addRequestor(CmpRequestorEntry requestor) {
        ParamUtil.requireNonNull("requestor", requestor);
        this.requestors.put(requestor.ident().name(), requestor);
    }

    public Set<String> getRequestorNames() {
        return Collections.unmodifiableSet(requestors.keySet());
    }

    public CmpRequestorEntry getRequestor(String name) {
        return requestors.get(ParamUtil.requireNonNull("name", name));
    }

    public void addPublisher(PublisherEntry publisher) {
        ParamUtil.requireNonNull("publisher", publisher);
        this.publishers.put(publisher.ident().name(), publisher);
    }

    public Set<String> getPublisherNames() {
        return Collections.unmodifiableSet(publishers.keySet());
    }

    public PublisherEntry getPublisher(String name) {
        return publishers.get(ParamUtil.requireNonNull("name", name));
    }

    public void addProfile(CertprofileEntry profile) {
        ParamUtil.requireNonNull("profile", profile);
        this.certprofiles.put(profile.ident().name(), profile);
    }

    public Set<String> getCertProfileNames() {
        return Collections.unmodifiableSet(certprofiles.keySet());
    }

    public CertprofileEntry getCertProfile(String name) {
        return certprofiles.get(ParamUtil.requireNonNull("name", name));
    }

    public void addSingleCa(SingleCaConf singleCa) {
        ParamUtil.requireNonNull("singleCa", singleCa);
        this.cas.put(singleCa.name(), singleCa);
    }

    public Set<String> getCaNames() {
        return Collections.unmodifiableSet(cas.keySet());
    }

    public SingleCaConf getCa(String name) {
        return cas.get(ParamUtil.requireNonNull("name", name));
    }

    public void addScep(ScepEntry scep) {
        ParamUtil.requireNonNull("scep", scep);
        this.sceps.put(scep.name(), scep);
    }

    public Set<String> getScepNames() {
        return Collections.unmodifiableSet(sceps.keySet());
    }

    public ScepEntry getScep(String name) {
        return sceps.get(ParamUtil.requireNonNull("name", name));
    }

    private String getValue(FileOrValueType fileOrValue, ZipFile zipFile) throws IOException {
        if (fileOrValue == null) {
            return null;
        }

        if (fileOrValue.getValue() != null) {
            return expandConf(fileOrValue.getValue());
        }

        String fileName = expandConf(fileOrValue.getFile());

        InputStream is;
        if (zipFile != null) {
            is = zipFile.getInputStream(new ZipEntry(fileName));
            if (is == null) {
                throw new IOException("could not find ZIP entry " + fileName);
            }
        } else {
            is = new FileInputStream(fileName);
        }
        byte[] binary = IoUtil.read(is);

        return expandConf(new String(binary, "UTF-8"));
    }

    private String getBase64Binary(FileOrBinaryType fileOrBinary, ZipFile zipFile)
            throws IOException {
        byte[] binary = getBinary(fileOrBinary, zipFile);
        return (binary == null) ? null : Base64.encodeToString(binary);
    }

    private byte[] getBinary(FileOrBinaryType fileOrBinary, ZipFile zipFile) throws IOException {
        if (fileOrBinary == null) {
            return null;
        }

        if (fileOrBinary.getBinary() != null) {
            return fileOrBinary.getBinary();
        }

        String fileName = expandConf(fileOrBinary.getFile());

        InputStream is;
        if (zipFile != null) {
            is = zipFile.getInputStream(new ZipEntry(fileName));
            if (is == null) {
                throw new IOException("could not find ZIP entry " + fileName);
            }
        } else {
            is = new FileInputStream(fileName);
        }

        return IoUtil.read(is);
    }

    private List<String> getStrings(StringsType jaxb) {
        if (jaxb == null) {
            return null;
        }

        List<String> ret = new ArrayList<>(jaxb.getStr().size());
        for (String m : jaxb.getStr()) {
            ret.add(expandConf(m));
        }
        return ret;
    }

    private String expandConf(String confStr) {
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
