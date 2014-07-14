/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.certprofile;

import java.io.ByteArrayInputStream;
import java.net.URL;
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.profile.AbstractCertProfile;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.CertificatePolicyInformation;
import org.xipki.ca.api.profile.CertificatePolicyQualifier;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.KeyUsage;
import org.xipki.ca.api.profile.RDNOccurrence;
import org.xipki.ca.api.profile.X509Util;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.server.certprofile.jaxb.ConstantExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.Admission;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.CertificateProfiles;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.server.certprofile.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.AllowedClientExtensions;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Subject;
import org.xipki.ca.server.certprofile.jaxb.RdnType;
import org.xipki.security.common.ObjectIdentifiers;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class DfltCertProfile extends AbstractCertProfile
{
    private static final Set<String> criticalOnlyExtensionTypes;
    private static final Set<String> noncriticalOnlyExtensionTypes;
    private static final Set<String> caOnlyExtensionTypes;

    private static final ASN1ObjectIdentifier id_extension_admission = new ASN1ObjectIdentifier("1.3.36.8.3.3");

    private ProfileType conf;

    private List<RDNOccurrence> subjectDNSubject;
    private Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;
    private Map<ASN1ObjectIdentifier, ExtensionOccurrence> additionalExtensionOccurences;

    private Integer validity;
    private boolean includeIssuerAndSerialInAKI;
    private boolean incSerialNrIfSubjectExists;
    private boolean raOnly;
    private boolean backwardsSubject;
    private boolean ca;
    private Integer pathLen;
    private Set<KeyUsage> keyusages;
    private Set<ASN1ObjectIdentifier> extendedKeyusages;

    private Set<ASN1ObjectIdentifier> allowedClientExtensions;

    private List<ASN1ObjectIdentifier> professionOIDs;
    private List<String> professionItems;

    private Map<ASN1ObjectIdentifier, Extension> constantExtensions;

    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    static
    {
        criticalOnlyExtensionTypes = new HashSet<>();
        criticalOnlyExtensionTypes.add(Extension.keyUsage.getId());
        criticalOnlyExtensionTypes.add(Extension.policyMappings.getId());
        criticalOnlyExtensionTypes.add(Extension.nameConstraints.getId());
        criticalOnlyExtensionTypes.add(Extension.policyConstraints.getId());
        criticalOnlyExtensionTypes.add(Extension.inhibitAnyPolicy.getId());

        noncriticalOnlyExtensionTypes = new HashSet<>();
        noncriticalOnlyExtensionTypes.add(Extension.authorityKeyIdentifier.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectKeyIdentifier.getId());
        noncriticalOnlyExtensionTypes.add(Extension.issuerAlternativeName.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectDirectoryAttributes.getId());
        noncriticalOnlyExtensionTypes.add(Extension.freshestCRL.getId());
        noncriticalOnlyExtensionTypes.add(Extension.authorityInfoAccess.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectInfoAccess.getId());

        caOnlyExtensionTypes = new HashSet<String>();
        caOnlyExtensionTypes.add(Extension.policyMappings.getId());
        caOnlyExtensionTypes.add(Extension.nameConstraints.getId());
        caOnlyExtensionTypes.add(Extension.policyConstraints.getId());
        caOnlyExtensionTypes.add(Extension.inhibitAnyPolicy.getId());
    }

    @Override
    public void initialize(String data)
    throws CertProfileException
    {
        this.conf = parse(data);
        this.raOnly = getBoolean(conf.isRaOnly(), false);
        this.validity = conf.getValidity();
        this.ca = conf.isCa();

        // Subject
        Subject subject = conf.getSubject();
        if(subject == null)
        {
            this.backwardsSubject = false;
            this.incSerialNrIfSubjectExists = false;
            this.subjectDNSubject = null;
        }
        else
        {
            this.backwardsSubject = subject.isDnBackwards();
            this.incSerialNrIfSubjectExists = subject.isIncSerialNrIfSubjectExists();

            List<RDNOccurrence> subjectDNSubject = new LinkedList<RDNOccurrence>();
            for(RdnType t : subject.getRdn())
            {
                RDNOccurrence occ = new RDNOccurrence(new ASN1ObjectIdentifier(t.getValue()),
                        getInt(t.getMinOccurs(), 1), getInt(t.getMaxOccurs(), 1));
                subjectDNSubject.add(occ);
            }

            this.subjectDNSubject = subjectDNSubject;
        }

        // Allowed extensions to be fulfilled by the client
        AllowedClientExtensions clientExtensions = conf.getAllowedClientExtensions();
        if(clientExtensions == null)
        {
            this.allowedClientExtensions = null;
        }
        else
        {
            this.allowedClientExtensions = new HashSet<>();
            for(String t : clientExtensions.getType())
            {
                this.allowedClientExtensions.add(new ASN1ObjectIdentifier(t));
            }
        }

        // Extensions
        ExtensionsType extensionsType = conf.getExtensions();

        this.pathLen = extensionsType.getPathLen();
        this.includeIssuerAndSerialInAKI = extensionsType.isIncludeIssuerAndSerialInAKI();

        // Extension KeyUsage
        org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage keyUsageTypes = extensionsType.getKeyUsage();
        if(keyUsageTypes == null)
        {
            this.keyusages = null;
        }
        else
        {
            Set<KeyUsage> set = new HashSet<>();
            for(KeyUsageType type : keyUsageTypes.getUsage())
            {
                switch(type)
                {
                case C_RL_SIGN:
                    set.add(KeyUsage.cRLSign);
                    break;
                case DATA_ENCIPHERMENT:
                    set.add(KeyUsage.dataEncipherment);
                    break;
                case CONTENT_COMMITMENT:
                    set.add(KeyUsage.contentCommitment);
                    break;
                case DECIPHER_ONLY:
                    set.add(KeyUsage.decipherOnly);
                    break;
                case ENCIPHER_ONLY:
                    set.add(KeyUsage.encipherOnly);
                    break;
                case DIGITAL_SIGNATURE:
                    set.add(KeyUsage.digitalSignature);
                    break;
                case KEY_AGREEMENT:
                    set.add(KeyUsage.keyAgreement);
                    break;
                case KEY_CERT_SIGN:
                    set.add(KeyUsage.keyCertSign);
                    break;
                case KEY_ENCIPHERMENT:
                    set.add(KeyUsage.keyEncipherment);
                    break;
                }
            }
            this.keyusages = Collections.unmodifiableSet(set);
        }

        // ExtendedKeyUsage
        ExtendedKeyUsage extKeyUsageType = extensionsType.getExtendedKeyUsage();
        if(extKeyUsageType == null)
        {
            this.extendedKeyusages = null;
        }
        else
        {
            Set<ASN1ObjectIdentifier> set = new HashSet<>();
            for(OidWithDescType type : extKeyUsageType.getUsage())
            {
                set.add(new ASN1ObjectIdentifier(type.getValue()));
            }
            this.extendedKeyusages = Collections.unmodifiableSet(set);
        }

        // admission
        Admission admissionType = extensionsType.getAdmission();
        List<String> l = admissionType == null ? null : admissionType.getProfessionItem();
        if(l == null || l.isEmpty())
        {
            this.professionItems = null;
        }
        else
        {
            this.professionItems = Collections.unmodifiableList(new LinkedList<>(l));
        }

        l =  admissionType == null ? null : admissionType.getProfessionOid();
        if(l == null || l.isEmpty())
        {
            this.professionOIDs = null;
        }
        else
        {
            List<ASN1ObjectIdentifier> oids = new LinkedList<>();
            for(String entry : l)
            {
                oids.add(new ASN1ObjectIdentifier(entry));
            }
            this.professionOIDs = Collections.unmodifiableList(oids);
        }

        // constant extensions
        ConstantExtensions ces = extensionsType.getConstantExtensions();
        if(ces == null)
        {
            this.constantExtensions = null;
        }
        else
        {
            this.constantExtensions = new HashMap<>();
            for(ConstantExtensionType ce :ces.getConstantExtension())
            {
                ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType());
                this.constantExtensions.put(type, new Extension(type, false, ce.getValue()));
            }
        }

        // Extension Occurrences
        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = new HashMap<>();
        for(ExtensionType extensionType : extensionsType.getExtension())
        {
            String oid = extensionType.getValue();
            if(ca == false && caOnlyExtensionTypes.contains(oid))
            {
                continue;
            }

            boolean required = extensionType.isRequired();
            Boolean b = extensionType.isCritical();

            boolean critical;
            if(criticalOnlyExtensionTypes.contains(oid))
            {
                critical = true;
            }
            else if(noncriticalOnlyExtensionTypes.contains(oid))
            {
                critical = false;
            }
            else if(ca && Extension.basicConstraints.getId().equals(oid))
            {
                critical = true;
            }
            else
            {
                critical = b == null ? false : b.booleanValue();
                if(critical && extendedKeyusages != null &&
                        extendedKeyusages.contains(ObjectIdentifiers.anyExtendedKeyUsage))
                {
                    critical = false;
                }
            }

            occurences.put(new ASN1ObjectIdentifier(oid),
                    ExtensionOccurrence.getInstance(critical, required));
        }

        this.extensionOccurences = Collections.unmodifiableMap(occurences);

        occurences = new HashMap<>(occurences);
        occurences.remove(Extension.authorityKeyIdentifier);
        occurences.remove(Extension.subjectKeyIdentifier);
        occurences.remove(Extension.authorityInfoAccess);
        occurences.remove(Extension.cRLDistributionPoints);
        occurences.remove(Extension.freshestCRL);
        occurences.remove(Extension.issuerAlternativeName);
        this.additionalExtensionOccurences = Collections.unmodifiableMap(occurences);
    }

    private static ProfileType parse(String xmlConf)
    throws CertProfileException
    {
        synchronized (jaxbUnmarshallerLock)
        {
            JAXBElement<?> rootElement;
            try
            {
                if(jaxbUnmarshaller == null)
                {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = DfltCertProfile.class.getResource("/xsd/certprofile.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(
                        new ByteArrayInputStream(xmlConf.getBytes()));
            }
            catch(JAXBException e)
            {
                throw new CertProfileException("parse profile failed, message: " + e.getMessage(), e);
            } catch (SAXException e)
            {
                throw new CertProfileException("parse profile failed, message: " + e.getMessage(), e);
            }

            Object rootType = rootElement.getValue();
            if(rootType instanceof ProfileType)
            {
                return (ProfileType) rootElement.getValue();
            }
            else
            {
                throw new CertProfileException("invalid root element type");
            }
        }
    }

    @Override
    public Integer getValidity()
    {
        return validity;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return extensionOccurences.get(Extension.authorityKeyIdentifier);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier()
    {
        return extensionOccurences.get(Extension.subjectKeyIdentifier);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfCRLDistributinPoints()
    {
        return extensionOccurences.get(Extension.cRLDistributionPoints);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return extensionOccurences.get(Extension.deltaCRLIndicator);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess()
    {
        return extensionOccurences.get(Extension.authorityInfoAccess);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return extensionOccurences.get(Extension.issuerAlternativeName);
    }

    @Override
    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = super.getExtensions(requestedSubject, requestedExtensions);

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = new HashMap<>(getAdditionalExtensionOccurences());
        // remove the extensions processed by the parent class
        occurences.remove(Extension.basicConstraints);
        occurences.remove(Extension.keyUsage);
        occurences.remove(Extension.extendedKeyUsage);

        // CertificatePolicies
        ASN1ObjectIdentifier extensionType = Extension.certificatePolicies;
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            List<CertificatePolicyInformation> policyInfos = getCertificatePolicies();
            CertificatePolicies value = X509Util.createCertificatePolicies(policyInfos);
            ExtensionTuple extension = createExtension(Extension.certificatePolicies,
                    occurence.isCritical(), value);
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // Admission
        extensionType = id_extension_admission;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = createAdmission(occurence.isCritical(),
                    professionOIDs, professionItems);
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // OCSP Nocheck
        extensionType = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = createExtension(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck,
                    occurence.isCritical(), DERNull.INSTANCE);
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // constant extensions
        if(constantExtensions != null)
        {
            for(ASN1ObjectIdentifier type : constantExtensions.keySet())
            {
                occurence = occurences.remove(type);

                if(occurence != null)
                {
                    ExtensionTuple extensionTuple = new ExtensionTuple(
                            occurence.isCritical(),
                            constantExtensions.get(type));
                    tuples.addExtension(extensionTuple);
                }
            }
        }

        // check whether there is unknown extensions
        if(occurences.isEmpty() == false)
        {
            StringBuilder sb = new StringBuilder("Extensions with the following types are not processed: ");
            for(ASN1ObjectIdentifier extnType : occurences.keySet())
            {
                sb.append(extnType.getId()).append(", ");
            }
            throw new CertProfileException(sb.substring(0, sb.length() - 2));
        }

        return tuples;
    }

    private ExtensionTuple retrieveExtensionTupleFromRequest(boolean critical, ASN1ObjectIdentifier extensionType,
            Extensions requestedExtensions)
    {
        // consider the Extensions contained in the request
        if(allowedClientExtensions == null || allowedClientExtensions.isEmpty())
        {
            return null;
        }

        Extension ext = requestedExtensions.getExtension(extensionType);
        return (ext == null) ? null :new ExtensionTuple(critical, ext);
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return incSerialNrIfSubjectExists;
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyusages;
    }

    @Override
    protected Set<ASN1ObjectIdentifier> getExtendedKeyUsages()
    {
        return extendedKeyusages;
    }

    @Override
    protected boolean isCa()
    {
        return ca;
    }

    @Override
    protected Integer getPathLenBasicConstraint()
    {
        return pathLen;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences()
    {
        return additionalExtensionOccurences;
    }

    @Override
    public boolean backwardsSubject()
    {
        return backwardsSubject;
    }

    @Override
    public boolean isOnlyForRA()
    {
        return raOnly;
    }

    @Override
    public boolean includeIssuerAndSerialInAKI()
    {
        return includeIssuerAndSerialInAKI;
    }

    private List<CertificatePolicyInformation> getCertificatePolicies()
    {
        CertificateProfiles xmlCertPolicies = conf.getExtensions().getCertificateProfiles();
        if(xmlCertPolicies == null)
        {
            return null;
        }

        List<CertificatePolicyInformationType> policyPairs = xmlCertPolicies.getCertificatePolicyInformation();
        if(policyPairs == null || policyPairs.isEmpty())
        {
            return null;
        }

        List<CertificatePolicyInformation> policies = new ArrayList<CertificatePolicyInformation>(policyPairs.size());
        for(CertificatePolicyInformationType policyPair : policyPairs)
        {
            List<CertificatePolicyQualifier> qualifiers = null;

            PolicyQualifiers policyQualifiers = policyPair.getPolicyQualifiers();
            if(policyQualifiers != null)
            {
                List<JAXBElement<String>> cpsUriOrUserNotice = policyQualifiers.getCpsUriOrUserNotice();

                qualifiers = new ArrayList<CertificatePolicyQualifier>(cpsUriOrUserNotice.size());
                for(JAXBElement<String> element : cpsUriOrUserNotice)
                {
                    String elementValue = element.getValue();
                    CertificatePolicyQualifier qualifier = null;
                    String elementName = element.getName().getLocalPart();
                    if("cpsUri".equals(elementName))
                    {
                        qualifier = CertificatePolicyQualifier.getInstanceForCpsUri(elementValue);
                    }
                    else
                    {
                        qualifier = CertificatePolicyQualifier.getInstanceForUserNotice(elementValue);
                    }
                    qualifiers.add(qualifier);
                }
            }

            CertificatePolicyInformation cpi = new CertificatePolicyInformation(
                    policyPair.getPolicyIdentifier(), qualifiers);

            policies.add(cpi);
        }

        return policies;
    }

    @Override
    public List<RDNOccurrence> getSubjectDNSubset()
    {
        return subjectDNSubject;
    }

    private static boolean getBoolean(Boolean b, boolean dfltValue)
    {
        return b == null ? dfltValue : b.booleanValue();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

    private ExtensionTuple createAdmission(boolean critical,
            List<ASN1ObjectIdentifier> professionOIDs,
            List<String> professionItems)
    throws CertProfileException
    {
        if(professionItems == null || professionItems.isEmpty())
        {
            if(professionOIDs == null || professionOIDs.isEmpty())
            {
                return null;
            }
        }

        DirectoryString[] _professionItems = null;
        if(professionItems != null && professionItems.size() > 0)
        {
            int n = professionItems.size();
            _professionItems = new DirectoryString[n];
            for(int i = 0; i < n; i++)
            {
                _professionItems[i] = new DirectoryString(professionItems.get(i));
            }
        }

        ASN1ObjectIdentifier[] _professionOIDs = null;
        if(professionOIDs != null && professionOIDs.size() > 0)
        {
            _professionOIDs = professionOIDs.toArray(new ASN1ObjectIdentifier[0]);
        }

        ProfessionInfo professionInfo = new ProfessionInfo(
                    null, _professionItems, _professionOIDs, null, null);

        Admissions admissions = new Admissions(null, null,
                new ProfessionInfo[]{professionInfo});

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(admissions);

        AdmissionSyntax value = new AdmissionSyntax(null, new DERSequence(vector));
        return createExtension(id_extension_admission, critical, value);
    }

}
