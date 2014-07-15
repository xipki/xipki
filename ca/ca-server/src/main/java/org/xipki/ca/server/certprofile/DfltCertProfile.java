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
import java.io.IOException;
import java.math.BigInteger;
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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.xipki.ca.api.profile.SubjectInfo;
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
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreesType;
import org.xipki.ca.server.certprofile.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.jaxb.PolicyIdMappingType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.AllowedClientExtensions;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Subject;
import org.xipki.ca.server.certprofile.jaxb.RdnType;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ObjectIdentifiers;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class DfltCertProfile extends AbstractCertProfile
{
    private static final Logger LOG = LoggerFactory.getLogger(DfltCertProfile.class);

    private static final Set<String> criticalOnlyExtensionTypes;
    private static final Set<String> noncriticalOnlyExtensionTypes;
    private static final Set<String> caOnlyExtensionTypes;

    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

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
    private GeneralNameType subjectAltNameMode;
    private GeneralNameType subjectInfoAccessMode;
    
    private ExtensionTuple certificatePolicies;
    private ExtensionTuple policyMappings;
    private ExtensionTuple nameConstraints;
    private ExtensionTuple policyConstraints;
    private ExtensionTuple inhibitAnyPolicy;
    private ExtensionTuple ocspNoCheck;
    private ExtensionTuple admission;

    private Map<ASN1ObjectIdentifier, ExtensionTuple> constantExtensions;

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
        try
        {
            ProfileType conf = parse(data);
            this.raOnly = getBoolean(conf.isOnlyForRA(), false);
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
                for(OidWithDescType t : clientExtensions.getType())
                {
                    this.allowedClientExtensions.add(new ASN1ObjectIdentifier(t.getValue()));
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
                    case CRL_SIGN:
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
                    case KEYCERT_SIGN:
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

            // Extension Occurrences
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurrences = new HashMap<>();
            for(ExtensionType extensionType : extensionsType.getExtension())
            {
                String oid = extensionType.getValue();
                if(ca == false && caOnlyExtensionTypes.contains(oid))
                {
                    LOG.warn("ignore CA-only extension {}", oid);
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

                if(b != null && b.booleanValue() != critical)
                {
                    LOG.warn("corrected the critical of extenion {} from {} to {}", new Object[]{oid, b, critical});
                }

                occurrences.put(new ASN1ObjectIdentifier(oid),
                        ExtensionOccurrence.getInstance(critical, required));
            }

            this.extensionOccurences = Collections.unmodifiableMap(occurrences);

            occurrences = new HashMap<>(occurrences);
            occurrences.remove(Extension.authorityKeyIdentifier);
            occurrences.remove(Extension.subjectKeyIdentifier);
            occurrences.remove(Extension.authorityInfoAccess);
            occurrences.remove(Extension.cRLDistributionPoints);
            occurrences.remove(Extension.freshestCRL);
            occurrences.remove(Extension.issuerAlternativeName);
            this.additionalExtensionOccurences = Collections.unmodifiableMap(occurrences);

            // Certificate Policies
            ASN1ObjectIdentifier extensionOid = Extension.certificatePolicies;
            ExtensionOccurrence occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getCertificateProfiles() != null)
            {
                CertificateProfiles type = extensionsType.getCertificateProfiles();
                List<CertificatePolicyInformation> policyInfos = buildCertificatePolicies(type);
                CertificatePolicies value = X509Util.createCertificatePolicies(policyInfos);
                this.certificatePolicies = createExtension(extensionOid,
                        occurrence.isCritical(), value);
            }

            // Policy Mappings
            extensionOid = Extension.policyMappings;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getPolicyMappings() != null)
            {
                org.bouncycastle.asn1.x509.PolicyMappings value = buildPolicyMappings(extensionsType.getPolicyMappings());
                this.policyMappings = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // Name Constrains
            extensionOid = Extension.nameConstraints;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getNameConstraints() != null)
            {
                NameConstraints value = buildNameConstrains(extensionsType.getNameConstraints());
                this.nameConstraints = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // Policy Constraints
            extensionOid = Extension.policyConstraints;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getPolicyConstraints() != null)
            {
                ASN1Sequence value = buildPolicyConstrains(extensionsType.getPolicyConstraints());
                this.policyConstraints = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // Inhibit anyPolicy
            extensionOid = Extension.inhibitAnyPolicy;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getInhibitAnyPolicy() != null)
            {
                int skipCerts = extensionsType.getInhibitAnyPolicy().getSkipCerts();
                if(skipCerts < 0)
                {
                       throw new CertProfileException("negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
                }
                DERInteger value = new DERInteger(skipCerts);
                this.inhibitAnyPolicy = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // OCSP NoCheck
            extensionOid = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null)
            {
                DERNull value = DERNull.INSTANCE;
                this.ocspNoCheck = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // admission
            extensionOid = ObjectIdentifiers.id_extension_admission;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getAdmission() != null)
            {
                List<ASN1ObjectIdentifier> professionOIDs;
                List<String> professionItems;

                Admission admissionType = extensionsType.getAdmission();
                List<String> items = admissionType == null ? null : admissionType.getProfessionItem();
                if(items == null || items.isEmpty())
                {
                    professionItems = null;
                }
                else
                {
                    professionItems = Collections.unmodifiableList(new LinkedList<>(items));
                }

                List<OidWithDescType> oidWithDescs =  admissionType == null ? null : admissionType.getProfessionOid();
                if(oidWithDescs == null || oidWithDescs.isEmpty())
                {
                    professionOIDs = null;
                }
                else
                {
                    List<ASN1ObjectIdentifier> oids = new LinkedList<>();
                    for(OidWithDescType entry : oidWithDescs)
                    {
                        oids.add(new ASN1ObjectIdentifier(entry.getValue()));
                    }
                    professionOIDs = Collections.unmodifiableList(oids);
                }

                this.admission = createAdmission(occurrence.isCritical(), professionOIDs, professionItems);
            }

            // SubjectAltNameMode
            this.subjectAltNameMode = extensionsType.getSubjectAltName();
            
            // SubjectInfoAccess
            this.subjectInfoAccessMode = extensionsType.getSubjectInfoAccess();

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
                    ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType().getValue());
                    occurrence = occurrences.get(type);
                    if(occurrence != null)
                    {
                        ASN1StreamParser parser = new ASN1StreamParser(ce.getValue());
                        ASN1Encodable value;
                        try
                        {
                            value = parser.readObject();
                        } catch (IOException e)
                        {
                            throw new CertProfileException("Could not parse the constant extension value", e);
                        }
                        ExtensionTuple tuple = createExtension(type, occurrence.isCritical(), value);
                        this.constantExtensions.put(type, tuple);
                    }
                }

                if(this.constantExtensions.isEmpty())
                {
                    this.constantExtensions = null;
                }
            }
        }catch(RuntimeException e)
        {
            LogUtil.logErrorThrowable(LOG, "RuntimeException", e);
            throw new CertProfileException("RuntimeException thrown while initializing certprofile: " + e.getMessage());
        }
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
        return extensionOccurences.get(Extension.freshestCRL);
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
    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
    	// remove the RDN with type subjectAltName and subjectInfoAccess
    	ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
    	boolean reconstruct = false;
    	for(ASN1ObjectIdentifier type : types)
    	{
    		if(type.equals(Extension.subjectAlternativeName) || type.equals(Extension.subjectInfoAccess))
    		{
    			reconstruct = true;
    			break;
    		}
    	}
    	
    	if(reconstruct)
    	{
    		List<RDN> newRdns = new LinkedList<>();
        	for(RDN rdn : requestedSubject.getRDNs())
        	{
        		ASN1ObjectIdentifier type = rdn.getFirst().getType();
        		if(type.equals(Extension.subjectAlternativeName) || type.equals(Extension.subjectInfoAccess))
        		{
        			continue;
        		}
        		newRdns.add(rdn);
        	}
        	
        	requestedSubject = new X500Name(newRdns.toArray(new RDN[0]));
    	}
    	
    	return super.getSubject(requestedSubject);
    }

    @Override
    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = super.getExtensions(requestedSubject, requestedExtensions);

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = new HashMap<>(getAdditionalExtensionOccurences());

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the parent class
        occurences.remove(Extension.keyUsage);

        // CertificatePolicies
        processExtension(tuples, occurences, Extension.certificatePolicies, certificatePolicies, requestedExtensions);

        // Policy Mappings
        processExtension(tuples, occurences, Extension.policyMappings, policyMappings, requestedExtensions);

        // SubjectAltName
        ASN1ObjectIdentifier extensionType = Extension.subjectAlternativeName;
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
	        ExtensionTuple extension = null;
        	if(subjectAltNameMode != null)
        	{
		        RDN[] rdns = requestedSubject.getRDNs(extensionType);
		        if(rdns != null && rdns.length > 0)
		        {
		        	final int n = rdns.length;
		        	GeneralName[] names = new GeneralName[n];
		        	for(int i = 0; i < n; i++)
		        	{
		        		String value = IETFUtils.valueToString(rdns[i].getFirst().getValue());
		        		names[i] = createGeneralName(value, subjectAltNameMode);
		        	}
		        	extension = createExtension(extensionType, occurence.isCritical(), new GeneralNames(names));
		        }
        	}
	        
	        if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // IssuerAltName
        // processed by the CA

        // Subject Directory Attributes
        // Will not supported

        // Basic Constraints
        // processed by the parent class
        occurences.remove(Extension.basicConstraints);

        // Name Constraints
        processExtension(tuples, occurences, Extension.nameConstraints, nameConstraints, requestedExtensions);

        // PolicyConstrains
        processExtension(tuples, occurences, Extension.policyConstraints, policyConstraints, requestedExtensions);

        // ExtendedKeyUsage
        // processed by the parent class
        occurences.remove(Extension.extendedKeyUsage);

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        processExtension(tuples, occurences, Extension.inhibitAnyPolicy, inhibitAnyPolicy, requestedExtensions);

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        extensionType = Extension.subjectInfoAccess;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
	        ExtensionTuple extension = null;
        	if(subjectInfoAccessMode != null)
        	{        		
		        RDN[] rdns = requestedSubject.getRDNs(extensionType);
		        if(rdns != null && rdns.length > 0)
		        {
		        	ASN1EncodableVector vector = new ASN1EncodableVector();
		             
		        	for(RDN rdn : rdns)
		        	{
		        		String value = IETFUtils.valueToString(rdn.getFirst().getValue());
		        		try{
			        		CmpUtf8Pairs pairs = new CmpUtf8Pairs(value);
			        		String accessMethod = pairs.getNames().iterator().next();
			        		String accessLocation = pairs.getValue(accessMethod);
			        		
			        		GeneralName location = createGeneralName(accessLocation, subjectInfoAccessMode);
				        	AccessDescription accessDescription = new AccessDescription(
				        			new ASN1ObjectIdentifier(accessMethod), location);
				        	vector.add(accessDescription);
		        		}catch(Exception e)
		        		{
		        			LOG.debug("Exception while processing subjectInfoAccess '{}': {}", value, e.getMessage());
		        			throw new BadCertTemplateException("invalid subjectInfoAccess '" + value + "'");
		        		}
		        	}
		        	
		        	ASN1Sequence seq = new DERSequence(vector);		        	
		        	extension = createExtension(extensionType, occurence.isCritical(), seq);
		        }
	        }
        	
	        if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // Admission
        processExtension(tuples, occurences, ObjectIdentifiers.id_extension_admission, admission, requestedExtensions);

        // OCSP Nocheck
        processExtension(tuples, occurences, ObjectIdentifiers.id_extension_pkix_ocsp_nocheck,
                ocspNoCheck, requestedExtensions);

        // constant extensions
        if(constantExtensions != null)
        {
            for(ASN1ObjectIdentifier type : constantExtensions.keySet())
            {
                occurence = occurences.remove(type);
                if(occurence != null)
                {
                    ExtensionTuple extensionTuple = constantExtensions.get(type);
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

    private static List<CertificatePolicyInformation> buildCertificatePolicies(CertificateProfiles type)
    {
        List<CertificatePolicyInformationType> policyPairs = type.getCertificatePolicyInformation();
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
                    policyPair.getPolicyIdentifier().getValue(), qualifiers);

            policies.add(cpi);
        }

        return policies;
    }

    private static PolicyMappings buildPolicyMappings(
            org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyMappings type)
    {
        List<PolicyIdMappingType> mappings = type.getMapping();
        final int n = mappings.size();

        CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
        CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

        for(int i = 0; i < n; i++)
        {
            PolicyIdMappingType mapping = mappings.get(i);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(mapping.getIssuerDomainPolicy().getValue());
            issuerDomainPolicy[i] = CertPolicyId.getInstance(oid);

            oid = new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getValue());
            subjectDomainPolicy[i] = CertPolicyId.getInstance(oid);
        }

        return new PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
    }

    private static NameConstraints buildNameConstrains(
            org.xipki.ca.server.certprofile.jaxb.ExtensionsType.NameConstraints type)
    throws CertProfileException
    {
        GeneralSubtree[] permitted = buildGeneralSubtrees(type.getPermittedSubtrees());
        GeneralSubtree[] excluded = buildGeneralSubtrees(type.getExcludedSubtrees());
        if(permitted == null && excluded == null)
        {
            return null;
        }
        return new NameConstraints(permitted, excluded);
    }

    private static GeneralSubtree[] buildGeneralSubtrees(GeneralSubtreesType subtrees)
    throws CertProfileException
    {
        if(subtrees == null || subtrees.getBase().isEmpty())
        {
            return null;
        }

        List<GeneralSubtreeBaseType> list = subtrees.getBase();
        final int n = list.size();
        GeneralSubtree[] ret = new GeneralSubtree[n];
        for(int i = 0; i < n; i++)
        {
            ret[i] = buildGeneralSubtree(list.get(i));
        }

        return ret;
    }

    private static GeneralSubtree buildGeneralSubtree(GeneralSubtreeBaseType type)
    throws CertProfileException
    {
        GeneralName base = null;
        if(type.getDirectoryName() != null)
        {
            base = new GeneralName(IoCertUtil.backwardSortX509Name(
                    new X500Name(type.getDirectoryName())));
        }
        else if(type.getDNSName() != null)
        {
            base = new GeneralName(GeneralName.dNSName, type.getDNSName());
        }
        else if(type.getIpAddress() != null)
        {
            base = new GeneralName(GeneralName.iPAddress, type.getIpAddress());
        }
        else if(type.getRfc822Name() != null)
        {
            base = new GeneralName(GeneralName.rfc822Name, type.getRfc822Name());
        }
        else if(type.getUri() != null)
        {
            base = new GeneralName(GeneralName.uniformResourceIdentifier, type.getUri());
        }
        else
        {
            throw new RuntimeException("should not reach here");
        }

        Integer i = type.getMinimum();
        if(i != null && i < 0)
        {
            throw new CertProfileException("negative minimum is not allowed: " + i);
        }

        BigInteger minimum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        i = type.getMaximum();
        if(i != null && i < 0)
        {
            throw new CertProfileException("negative maximum is not allowed: " + i);
        }

        BigInteger maximum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        return new GeneralSubtree(base, minimum, maximum);
    }

    private static ASN1Sequence buildPolicyConstrains(PolicyConstraints type)
    throws CertProfileException
    {
        Integer requireExplicitPolicy = type.getRequireExplicitPolicy();
        if(requireExplicitPolicy != null && requireExplicitPolicy < 0)
        {
            throw new CertProfileException("negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
        }

        Integer inhibitPolicyMapping = type.getInhibitPolicyMapping();
        if(inhibitPolicyMapping != null && inhibitPolicyMapping < 0)
        {
            throw new CertProfileException("negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
        }

        if(requireExplicitPolicy == null && inhibitPolicyMapping == null)
        {
            return null;
        }

        final boolean explicit = false;
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (requireExplicitPolicy != null)
        {
            vec.add(new DERTaggedObject(explicit, 0, new DERInteger(requireExplicitPolicy)));
        }

        if (inhibitPolicyMapping != null)
        {
            vec.add(new DERTaggedObject(explicit, 1, new DERInteger(inhibitPolicyMapping)));
        }

        return new DERSequence(vec);
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
        return createExtension(ObjectIdentifiers.id_extension_admission, critical, value);
    }

    private void processExtension(ExtensionTuples tuples,
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences,
            ASN1ObjectIdentifier extensionType,
            ExtensionTuple preferredExtension,
            Extensions requestedExtensions)
    throws CertProfileException
    {
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = preferredExtension;
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }
    }

    private static GeneralName createGeneralName(String value, GeneralNameType mode)
    {
    	GeneralName ret;
    	if(mode.getDirectoryName() != null)
    	{
    		X500Name name = IoCertUtil.backwardSortX509Name(new X500Name(value));
    		ret = new GeneralName(name);
    	}
    	else if(mode.getDNSName() != null)
    	{
    		ret = new GeneralName(GeneralName.dNSName, value);
    	}
    	else if(mode.getIPAddress() != null)
    	{
    		ret = new GeneralName(GeneralName.iPAddress, value);
    	}
    	else if(mode.getOtherName() != null)
    	{
    		String type = mode.getOtherName().getType().getValue();
    		
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1ObjectIdentifier(type));
            DERTaggedObject taggedObject = new DERTaggedObject(true, 0, new DERUTF8String(value));
            vector.add(taggedObject);
            DERSequence otherName = new DERSequence(vector);
            ret = new GeneralName(GeneralName.otherName, otherName);
    	}
    	else if(mode.getRegisteredID() != null)
    	{
    		ret = new GeneralName(GeneralName.registeredID, value);
    	}
    	else if(mode.getRfc822Name() != null)
    	{
    		ret = new GeneralName(GeneralName.rfc822Name, value);
    	}
    	else if(mode.getUniformResourceIdentifier() != null)
    	{
    		ret = new GeneralName(GeneralName.uniformResourceIdentifier, value);
    	}
    	else
    	{
    		throw new RuntimeException("should not reach here");
    	}
    	
    	return ret;
    }
}
