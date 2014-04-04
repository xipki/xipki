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

package org.xipki.ca.client.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.IdentifiedCertProfile;
import org.xipki.ca.api.profile.OriginalProfileConf;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.cmp.client.AbstractRAWorker;
import org.xipki.ca.cmp.client.CmpRequestorException;
import org.xipki.ca.cmp.client.type.CRLResultType;
import org.xipki.ca.cmp.client.type.CmpResultType;
import org.xipki.ca.cmp.client.type.EnrollCertEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.EnrollCertResultType;
import org.xipki.ca.cmp.client.type.ErrorResultEntryType;
import org.xipki.ca.cmp.client.type.ErrorResultType;
import org.xipki.ca.cmp.client.type.ResultEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertRequestEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertRequestType;
import org.xipki.ca.cmp.client.type.RevocateCertResultEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertResultType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.DfltEnvironmentParameterResolver;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public final class RAWorkerImpl extends AbstractRAWorker implements RAWorker
{	
	/**
	 * The certificate of the responder.
	 */
	public static final String REQUESTOR_CERT = "requestor.cert";
	
	/**
	 * The type of requestorSigner signer
	 */
	public static final String REQUESTOR_SIGNER_TYPE = "requestor.signer.type";

	/**
	 * The configuration of the requestorSigner signer
	 */
	public static final String REQUESTOR_SIGNER_CONF = "requestor.signer.conf";
	
	public static final String CA_PREFIX = "ca.";
	
	public static final String CA_ENABLED_SUFFIX = ".enabled";
	
	/**
	 * certificate of the given CA
	 */
	public static final String CA_CERT_SUFFIX = ".cert";
	
	/**
	 * URL of the given CA 
	 */
	public static final String CA_URL_SUFFIX = ".url";

	public static final String CA_RESPONDER_SUFFIX = ".responder";

	/**
	 * Certificate profiles supported by the given CA
	 */
	public static final String CA_PROFILES_SUFFIX = ".profiles";
	
	/**
	 * Certificate Profiles definition
	 */
	public static final String CERTPROFILE_PREFIX = "profile.";
	public static final String CERTPROFILE_TYPE_SUFFIX = ".type";
	public static final String CERTPROFILE_CONF_SUFFIX = ".conf";
	
	/**
	 * Certificate Profiles of RA
	 */
	public static final String RA_PROFILE_PREFIX = "ra.profile.";
	public static final String RA_PROFILE_CA_SUFFIX = ".ca";
	public static final String RA_PROFILE_TARGETPROFILE_SUFFIX = ".target";
	
	/**
	 * Environment parameter
	 */
	public static final String ENV_PREFIX = "env.";
	
	private static final Logger LOG = LoggerFactory.getLogger(RAWorkerImpl.class);
	
	public static long DAY = 24L * 60 * 60 * 1000;
	
	private final Map<String, CAConf> casMap = new HashMap<String, CAConf>();
	private final Map<String, X509CmpRequestor> cmpRequestorsMap = new ConcurrentHashMap<String, X509CmpRequestor>();
	private final Map<String, IdentifiedCertProfile> raProfilesMaps = new ConcurrentHashMap<String, IdentifiedCertProfile>();
	private final Map<String, RACertProfileMapping> raProfileMappingsMap
			= new ConcurrentHashMap<String, RACertProfileMapping>();
		
    private String            confFile;
    
	public RAWorkerImpl()
	{
	}	

	public void init()
	throws ConfigurationException, IOException
	{
		ParamChecker.assertNotNull("confFile", confFile);
		ParamChecker.assertNotNull("passwordResolver", passwordResolver);
		ParamChecker.assertNotNull("securityFactory", securityFactory);
        
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
 
		Properties props = new Properties();
		FileInputStream configStream = new FileInputStream(confFile);
		try{
			props.load(configStream);
		}finally{
			try{
				configStream.close();
			}catch(IOException e)
			{}
		}
		
		X509Certificate requestorCert = null;
		String s = props.getProperty(REQUESTOR_CERT);
		if(!isEmpty(s))
		{
			try {
				requestorCert = IoCertUtil.parseCert(s);
			} catch (Exception e) {
				throw new ConfigurationException(e);
			}
		}
		
		String requestorSignerType = props.getProperty(REQUESTOR_SIGNER_TYPE);
		String requestorSignerConf = props.getProperty(REQUESTOR_SIGNER_CONF);		
		
		Set<String> canames = new HashSet<String>();
		Set<String> disabledCaNames = new HashSet<String>();
		
		for(Object _propKey : props.keySet())
		{
			String propKey = (String) _propKey;
			if(propKey.startsWith(CA_PREFIX) && propKey.endsWith(CA_CERT_SUFFIX))
			{
				String caname = propKey.substring(CA_PREFIX.length(),
						propKey.length() - CA_CERT_SUFFIX.length());
				
				String enabled = props.getProperty(CA_PREFIX + caname + CA_ENABLED_SUFFIX, "true");
				if(Boolean.parseBoolean(enabled))
				{
					canames.add(caname);
				}
				else
				{
					LOG.info("CA " + caname + " is disabled");
					disabledCaNames.add(caname);
				}
			}
		}
		
		if(canames.isEmpty())
		{
			throw new ConfigurationException("No CAConf configured");
		}

		Set<String> configuredCaNames = new HashSet<String>();
		
		Set<CAConf> cas = new HashSet<CAConf>();
		for(String caname : canames)
		{
			try{
				String _serviceUrl = props.getProperty(CA_PREFIX + caname + CA_URL_SUFFIX);
				String _cacertFile = props.getProperty(CA_PREFIX + caname + CA_CERT_SUFFIX);
				String _responderFile = props.getProperty(CA_PREFIX + caname + CA_RESPONDER_SUFFIX);
				String _profiles = props.getProperty(CA_PREFIX + caname + CA_PROFILES_SUFFIX);
				StringTokenizer st = new StringTokenizer(_profiles, ",");
				Set<String> profiles = new HashSet<String>(st.countTokens());
				while(st.hasMoreTokens())
				{
					profiles.add(st.nextToken().trim());
				}

				CAConf ca = new CAConf(caname, _serviceUrl, IoCertUtil.parseCert(_cacertFile), profiles,
						IoCertUtil.parseCert(_responderFile));
				cas.add(ca);
				configuredCaNames.add(caname);
			}catch(Exception e)
			{
				LOG.warn("Could not configure CA {}, {}", caname, e.getMessage());
				LOG.debug("Could not configure CA " + caname, e);
			}
		}
		
		// environment parameters
		DfltEnvironmentParameterResolver envParamsResolver = new DfltEnvironmentParameterResolver();
		for(Object _propKey : props.keySet())
		{
			String propKey = (String) _propKey;
			if(propKey.startsWith(ENV_PREFIX))
			{
				String name = propKey.substring(ENV_PREFIX.length());
				envParamsResolver.addEnvParam(name, props.getProperty(propKey));
			}
		}
			
		// Certificate profiles
		Set<String> certProfileNames = new HashSet<String>();		
		for(Object _propKey : props.keySet())
		{
			String propKey = (String) _propKey;
			if(propKey.startsWith(CERTPROFILE_PREFIX) && propKey.endsWith(CERTPROFILE_TYPE_SUFFIX))
			{
				String name = propKey.substring(CERTPROFILE_PREFIX.length(),
						propKey.length() - CERTPROFILE_TYPE_SUFFIX.length());
				certProfileNames.add(name);
			}
		}
		
		Set<IdentifiedCertProfile> certProfiles = new HashSet<IdentifiedCertProfile>();
		for(String name : certProfileNames)
		{
			String type = props.getProperty(CERTPROFILE_PREFIX + name + CERTPROFILE_TYPE_SUFFIX);
			String conf = props.getProperty(CERTPROFILE_PREFIX + name + CERTPROFILE_CONF_SUFFIX);
			
			CertProfile underlyingCertProfile = null;
			if(type.toLowerCase().startsWith("java:"))
			{
				String className = type.substring("java:".length());
				try{
					Class<?> clazz = Class.forName(className);			
					underlyingCertProfile = (CertProfile) clazz.newInstance();
				}catch(Exception e)
				{
					throw new ConfigurationException("invalid type " + type);
				}
			}
			else
			{
				throw new ConfigurationException("invalid type " + type);
			}
			
			IdentifiedCertProfile certProfile = new IdentifiedCertProfile(name, underlyingCertProfile);
			try {
				certProfile.initialize(conf);
			} catch (CertProfileException e) {
				throw new ConfigurationException("invalid for certprofile name = " + name + ", message: " + e.getMessage());
			}
			certProfile.setEnvironmentParamterResolver(envParamsResolver);
			
			certProfiles.add(certProfile);
		}
		
		Set<String> raProfileNames = new HashSet<String>();
		for(Object _propKey : props.keySet())
		{
			String propKey = (String) _propKey;
			if(propKey.startsWith(RA_PROFILE_PREFIX) && propKey.endsWith(RA_PROFILE_CA_SUFFIX))
			{
				String name = propKey.substring(RA_PROFILE_PREFIX.length(),
						propKey.length() - RA_PROFILE_CA_SUFFIX.length());
				String destCA = props.getProperty(RA_PROFILE_PREFIX + name + RA_PROFILE_CA_SUFFIX);
				if(canames.contains(destCA))
				{
					if(configuredCaNames.contains(destCA))
					{
						raProfileNames.add(name);
					}
					else
					{
						LOG.info("destCA " + destCA + " could not be initialized, ignore cert profile " + name + "");
					}
				}
				else if(disabledCaNames.contains(destCA))
				{				
					LOG.info("destCA " + destCA + " is disabled, ignore cert profile " + name + "");
				}
				else
				{
					throw new ConfigurationException("no CA " + destCA + " defined");
				}
			}
		}
		
		Set<RACertProfileMapping> raCertProfileMappings = new HashSet<RACertProfileMapping>();		
		for(String name : raProfileNames)
		{
			String ca = props.getProperty(RA_PROFILE_PREFIX + name + RA_PROFILE_CA_SUFFIX);
			String targetProfile = props.getProperty(RA_PROFILE_PREFIX + name + RA_PROFILE_TARGETPROFILE_SUFFIX);
			raCertProfileMappings.add(new RACertProfileMapping(name, targetProfile, ca));			
		}
		
		// ------------------------------------------------		
		ConcurrentContentSigner requestorSigner;
		try {
			requestorSigner = securityFactory.createSigner(
					requestorSignerType, requestorSignerConf, requestorCert, passwordResolver);
		} catch (SignerException e) {
			throw new ConfigurationException(e);
		} catch (PasswordResolverException e) {
			throw new ConfigurationException(e);
		}		
		
		for(CAConf ca :cas)
		{
			if(null != this.casMap.put(ca.getName(), ca))
			{
				throw new IllegalArgumentException("duplicate CAs with the same name " + ca.getName());
			}
			
			X509CmpRequestor cmpRequestor = new DefaultHttpCmpRequestor(
					requestorSigner, ca.getResponder(), ca.getCert(), ca.getUrl(),
					securityFactory);
			
			cmpRequestorsMap.put(ca.getName(), cmpRequestor);
		}
		
		for(IdentifiedCertProfile profile : certProfiles)
		{
			String name = profile.getName();
			if(this.raProfilesMaps.containsKey(name))
			{
				throw new IllegalArgumentException("Cert profile " + name + " defined duplicatedly");
			}
			this.raProfilesMaps.put(name, profile);
		}
		
		for(RACertProfileMapping mapping : raCertProfileMappings)
		{
			String ca = mapping.getDestCA();
			String requestedProfile = mapping.getRequestedProfile();
			String destProfile = mapping.getDestProfile();
			
			if(! this.raProfilesMaps.containsKey(requestedProfile))
			{
				throw new ConfigurationException(
						"RAClient requested profile " + requestedProfile + " not configured"); 
			}
			
			boolean destProfileSupported = this.casMap.get(mapping.getDestCA()).getProfiles().contains(destProfile);
			
			if(! destProfileSupported)
			{
				throw new ConfigurationException("RAClient dest profile " + destProfile +
						" not supported by CA " + ca);
			}
			this.raProfileMappingsMap.put(requestedProfile, mapping);
		}
	}

	@Override
	public EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName)
	throws RAWorkerException, PKIErrorException
	{
		EnrollCertEntryType entry = new EnrollCertEntryType(p10Request, profile);
		Map<String, EnrollCertEntryType> entries = new HashMap<String, EnrollCertEntryType>();
		
		final String id = "p10-1";
		entries.put(id, entry);
		return requestCerts(EnrollCertRequestType.Type.CERT_REQ, entries, caName);
	}

	@Override
	public EnrollCertResult requestCerts(EnrollCertRequestType.Type type, 
			Map<String, EnrollCertEntryType> enrollCertEntries,
			String caname)
	throws RAWorkerException, PKIErrorException
	{
		ParamChecker.assertNotNull("enrollCertEntries", enrollCertEntries);

		if(enrollCertEntries.isEmpty())
		{
			return null;
		}

		EnrollCertRequestType enrollCertRequest = new EnrollCertRequestType(type);
		
		for(String id : enrollCertEntries.keySet())
		{
			EnrollCertEntryType entry = enrollCertEntries.get(id);
			
			CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
				
			CertificationRequestInfo p10ReqInfo = entry.getP10Request().getCertificationRequestInfo();
			certTempBuilder.setPublicKey(p10ReqInfo.getSubjectPublicKeyInfo());
			certTempBuilder.setSubject(p10ReqInfo.getSubject());
				
			// TODO: extract the extensions from the attributes		
			CertTemplate certTemplate = certTempBuilder.build();
			CertRequest certReq = new CertRequest(1, certTemplate, null);

			EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType(
					id, entry.getProfile(), certReq, raVerified);
			enrollCertRequest.addRequestEntry(requestEntry);
		}
		
		return requestCerts(enrollCertRequest, caname);
	}
	
	@Override
	public EnrollCertResult requestCert(CertReqMsg request, String extCertReqId, String caName) 
	throws RAWorkerException, PKIErrorException
	{
		ParamChecker.assertNotNull("request", request);
		X509CmpRequestor cmpRequestor = getCmpRequestor(request, caName);
		
		CmpResultType result;
		try {
			result = cmpRequestor.requestCertificate(request, extCertReqId);
		} catch (CmpRequestorException e) {
			throw new RAWorkerException(e);
		}
		
		if(result instanceof ErrorResultType)
		{
			throw createPKIErrorException((ErrorResultType) result);
		}
		else if(result instanceof EnrollCertResultType)
		{
			return parseEnrollCertResult((EnrollCertResultType) result, caName);
		}
		else
		{
			throw new RuntimeException("Unknown result type: " + result.getClass().getName());
		}
	}
	
	@Override
	public CertReqMsg getCertReqMsgWithAppliedCertProfile(CertRequest request,
			String profileName, ProofOfPossession popo)
	throws RAWorkerException {
		boolean shouldApplyCertProfile = false;

		String caName;
		if(raProfileMappingsMap.containsKey(profileName))
		{
			caName = raProfileMappingsMap.get(profileName).getDestCA();
			shouldApplyCertProfile = true;
		}
		else
		{
			caName = getCANameForProfile(profileName);
			if(caName == null)
			{
				throw new RAWorkerException("CertProfile " + profileName + " is not supported by any CA"); 
			}
		}
				
		if (shouldApplyCertProfile)
		{
			return applyCertProfile(profileName, request, popo);
		}
		else
		{
			AttributeTypeAndValue certProfileInfo = null;
			if(profileName != null)
			{
				CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE, profileName);
				certProfileInfo = new AttributeTypeAndValue(
						CMPObjectIdentifiers.regInfo_utf8Pairs, new DERUTF8String(utf8Pairs.getEncoded()));
			}
			
			return new CertReqMsg(request, popo, (certProfileInfo == null) ? null
	                : new AttributeTypeAndValue[] { certProfileInfo });
		}
	}
	
	private CertReqMsg applyCertProfile(
			String profileName, CertRequest origCertRequest, ProofOfPossession popo) 
	throws RAWorkerException {
        CertRequest newCertRequest = applyCertProfile(origCertRequest, profileName);
		
		if(popo != null)
		{
			popo = raVerified;
		}
		
		OriginalProfileConf origProfileConf = buildOriginalProfileConf(profileName);
		String encodedOrigProfile = origProfileConf.getEncoded();
		
        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(
                CmpUtf8Pairs.KEY_CERT_PROFILE, raProfileMappingsMap.get(profileName).getDestProfile());
       	utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_ORIG_CERT_PROFILE, encodedOrigProfile);
            
        AttributeTypeAndValue certProfileInfo = new AttributeTypeAndValue(
                    CMPObjectIdentifiers.regInfo_utf8Pairs, 
                    new DERUTF8String(utf8Pairs.getEncoded()));

		return new CertReqMsg(newCertRequest, popo, new AttributeTypeAndValue[] { certProfileInfo });
	}
	
	private CertRequest applyCertProfile(CertRequest origCertRequest, String profileName) throws RAWorkerException
	{
		CertProfile certProfile = raProfilesMaps.get(profileName);
		
		CertTemplate origCertTemp = origCertRequest.getCertTemplate();
		
		CertTemplateBuilder builder = new CertTemplateBuilder();
		builder.setPublicKey(origCertTemp.getPublicKey());
		
		X500Name requestedSubject = origCertTemp.getSubject();
		X500Name newSubject;
		try {
			newSubject = certProfile.getSubject(requestedSubject).getGrantedSubject();
		} catch (CertProfileException e) {
			throw new RAWorkerException(e);
		} catch (BadCertTemplateException e) {
			throw new RAWorkerException(e);
		}
		builder.setSubject(newSubject);
		
		Integer validity = certProfile.getValidity();
		if(validity != null)
		{
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + DAY * validity);
			
			OptionalValidity optionalValidity = new OptionalValidity(new Time(notBefore), new Time(notAfter));
			builder.setValidity(optionalValidity);
		}
		
		List<ExtensionTuple> extensionTuples;
		try {
			extensionTuples = certProfile.getExtensions(requestedSubject, origCertTemp.getExtensions()).getExtensions();
		} catch (CertProfileException e) {
			throw new RAWorkerException(e);
		} catch (BadCertTemplateException e) {
			throw new RAWorkerException(e);
		}

		List<Extension> newExtensions = new ArrayList<Extension>(extensionTuples.size());

		for(ExtensionTuple extension : extensionTuples)
		{
			byte[] encodedValue;
			try {
				encodedValue = extension.getValue().toASN1Primitive().getEncoded();
			} catch (IOException e) {
				throw new RAWorkerException("Error while decode the extension " + extension.getType().getId());
			}
			Extension newExtension = new Extension(
					extension.getType(),
					extension.isCritical(),
					encodedValue);
			newExtensions.add(newExtension);
		}
		
		Extensions extensions = new Extensions(newExtensions.toArray(new Extension[0]));

		builder.setExtensions(extensions);
		
		return new CertRequest(origCertRequest.getCertReqId(),
				builder.build(), origCertRequest.getControls());
	}
	
	@Override
	public EnrollCertResult requestCerts(EnrollCertRequestType request, String caname)
	throws RAWorkerException, PKIErrorException
	{
		ParamChecker.assertNotNull("request", request);
		
		List<EnrollCertRequestEntryType> requestEntries = request.getRequestEntries();
		if(requestEntries.isEmpty())
		{
			return null;
		}
		
		if(caname == null)
		{
			// detect the CA name
			String profile = requestEntries.get(0).getCertProfile();
			if(raProfileMappingsMap.containsKey(profile))
			{
				caname = raProfileMappingsMap.get(profile).getDestCA();
			}
			else
			{
				caname = getCANameForProfile(profile);
				if(caname == null)
				{
					throw new RAWorkerException("CertProfile " + profile + " is not supported by any CA"); 
				}
			}
		}

		// make sure that all requests are targeted on the same CA
		boolean shouldApplyCertProfile = false;
		for(EnrollCertRequestEntryType entry : request.getRequestEntries())
		{
			String profile = entry.getCertProfile();
			if(raProfileMappingsMap.containsKey(profile))
			{
				shouldApplyCertProfile = true;
				RACertProfileMapping raProfileMapping = raProfileMappingsMap.get(profile);
				if(! raProfileMapping.getDestCA().equals(caname))
				{
					throw new RAWorkerException("Not all requests are targeted on the same CA");
				}
			}
			else
			{
				checkCertProfileSupportInCA(profile, caname);
			}
		}
		
		X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caname);
		if(cmpRequestor == null)
		{
			throw new RAWorkerException("could not find CA named " + caname);
		}
		
		if(shouldApplyCertProfile)
		{
			request = applyCertProfiles(request);
		}
		
		CmpResultType result;
		try {
			result = cmpRequestor.requestCertificate(request);
		} catch (CmpRequestorException e) {
			throw new RAWorkerException(e);
		}
		
		if(result instanceof ErrorResultType)
		{
			throw createPKIErrorException((ErrorResultType) result);
		}
		else if(result instanceof EnrollCertResultType)
		{
			return parseEnrollCertResult((EnrollCertResultType) result, caname);
		}
		else
		{
			throw new RuntimeException("Unknown result type: " + result.getClass().getName());
		}
	}
	
	private EnrollCertRequestType applyCertProfiles(EnrollCertRequestType request) 
			throws RAWorkerException
	{
		EnrollCertRequestType ret = new EnrollCertRequestType(request.getType());
		
		for(EnrollCertRequestEntryType singleRequest : request.getRequestEntries())
		{
			String profileName = singleRequest.getCertProfile();
			if(raProfilesMaps.containsKey(profileName))
			{
				singleRequest = applyCertProfile(profileName, singleRequest);
			}
			ret.addRequestEntry(singleRequest);
		}

		return ret;
	}
	
	private EnrollCertRequestEntryType applyCertProfile(
			String profileName,
			EnrollCertRequestEntryType singleRequest) 
	throws RAWorkerException
	{
		RACertProfileMapping raCertProfileMapping = raProfileMappingsMap.get(profileName);
		ProofOfPossession popo = singleRequest.getPopo();
		if(popo != null)
		{
			popo = raVerified;
		}
		
		CertRequest newCertRequest = applyCertProfile(singleRequest.getCertReq(), profileName);
		
		EnrollCertRequestEntryType ret = new EnrollCertRequestEntryType(singleRequest.getId(), 
				raCertProfileMapping.getDestProfile(), newCertRequest, popo);
		
		OriginalProfileConf origProfileConf = buildOriginalProfileConf(profileName);
		ret.setOrigCertProfile(origProfileConf.getEncoded());
		return ret;
	}
	
	private void checkCertProfileSupportInCA(String certProfile, String caname)
	throws RAWorkerException
	{
		if(caname == null){
			for(CAConf ca : casMap.values())
			{
				if(ca.getProfiles().contains(certProfile))
				{
					if(caname == null)
					{
						caname = ca.getName();
					}
					else
					{
						throw new RAWorkerException("Certificate profile " + certProfile + 
								" supported by more than one CA, please specify the CA name.");
					}
				}
			}
			
			if(caname == null)
			{
				throw new RAWorkerException("Unsupported certificate profile " + certProfile);
			}
		}
		
		else if(!casMap.containsKey(caname))
		{
			throw new RAWorkerException("unknown ca: " + caname);
		}
		else
		{
			CAConf ca = casMap.get(caname);
			if(! ca.getProfiles().contains(certProfile))
			{
				throw new RAWorkerException("cert profile " + certProfile + " is not supported by the CA " + caname);
			}
		}
	}

	private OriginalProfileConf buildOriginalProfileConf(String profileName)
	{
		CertProfile certProfile = raProfilesMaps.get(profileName);
		OriginalProfileConf origProfileConf = new OriginalProfileConf(profileName);
		origProfileConf.setAuthorityInfoAccess(certProfile.getOccurenceOfAuthorityInfoAccess());
		origProfileConf.setAuthorityKeyIdentifier(certProfile.getOccurenceOfAuthorityKeyIdentifier());
		origProfileConf.setCRLDisributionPoints(certProfile.getOccurenceOfCRLDistributinPoints());
		origProfileConf.setSubjectKeyIdentifier(certProfile.getOccurenceOfSubjectKeyIdentifier());
		return origProfileConf;
	}
	
	@Override
	public CertIDOrError revocateCert(X509Certificate cert, int reason)
			throws RAWorkerException, PKIErrorException 
	{
		X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
		return revocateCert(issuer, cert.getSerialNumber(), reason);
	}

	@Override
	public CertIDOrError revocateCert(X500Name issuer, BigInteger serial, int reason)
	throws RAWorkerException, PKIErrorException
	{
		final String id = "revcert-1";
		RevocateCertRequestEntryType entry = 
				new RevocateCertRequestEntryType(id, issuer, serial, reason, new Date());
		RevocateCertRequestType request = new RevocateCertRequestType();
		request.addRequestEntry(entry);
		Map<String, CertIDOrError> result = revocateCerts(request);
		return result == null ? null : result.get(id);
	}

	@Override
	public Map<String, CertIDOrError> revocateCerts(RevocateCertRequestType request)
	throws RAWorkerException, PKIErrorException
	{
		ParamChecker.assertNotNull("request", request);

		List<RevocateCertRequestEntryType> requestEntries = request.getRequestEntries();
		if(requestEntries.isEmpty())
		{
			return Collections.emptyMap();
		}		
		
		X500Name issuer = requestEntries.get(0).getIssuer();
		
		for(int i = 1; i < requestEntries.size(); i++)
		{
			if(issuer.equals(requestEntries.get(i).getIssuer()))
			{
				throw new IllegalArgumentException("Revocating certificates issued by more than one CA is not allowed");
			}
		}




		final String caname = getCaNameByIssuer(issuer);



		X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caname);

		CmpResultType result;
		try {
			result = cmpRequestor.revocateCertificate(request);
		} catch (CmpRequestorException e) {
			throw new RAWorkerException(e);
		}
		
		if(result instanceof ErrorResultType)
		{
			throw createPKIErrorException((ErrorResultType) result);
		}
		else if(result instanceof RevocateCertResultType)
		{
			Map<String, CertIDOrError> ret = new HashMap<String, CertIDOrError>();

			RevocateCertResultType _result = (RevocateCertResultType) result;
			for(ResultEntryType _entry : _result.getResultEntries())
			{
				CertIDOrError certIdOrError;
				if(_entry instanceof RevocateCertResultEntryType)
				{
					RevocateCertResultEntryType entry = (RevocateCertResultEntryType) _entry;
					certIdOrError = new CertIDOrError(entry.getCertID());
				}
				else if(_entry instanceof ErrorResultEntryType)
				{
					ErrorResultEntryType entry = (ErrorResultEntryType) _entry;
					certIdOrError = new CertIDOrError(entry.getStatusInfo());
				}
				else
				{
					throw new RAWorkerException("unknwon type " + _entry);
				}

				ret.put(_entry.getId(), certIdOrError);
				// TODO: check the whether the serial number and issuer match the requested ones.
			}
			
			return ret;
		}
		else
		{
			throw new RuntimeException("Unknown result type: " + result.getClass().getName());
		}
	}
	
	@Override
	public X509CRL downloadCRL(String caname)
	throws RAWorkerException, PKIErrorException
	{
		return requestCRL(caname, false);
	}

	@Override
	public X509CRL generateCRL(String caname)
	throws RAWorkerException, PKIErrorException
	{
		return requestCRL(caname, true);
	}

    @Override
    public String getCaNameByIssuer(final X500Name issuer) throws RAWorkerException {

        if(issuer ==null ){
            throw new RAWorkerException("Invalid issuer");
        }

        for(String name : casMap.keySet())
        {
            final CAConf ca = casMap.get(name);
            if(ca.getSubject().equals(issuer))
            {
                return name;
            }
        }

        throw new RAWorkerException("Unknown CA for issuer: " + issuer);
    }

    private X509CRL requestCRL(String caname, boolean generateCRL)
	throws RAWorkerException, PKIErrorException
	{
		ParamChecker.assertNotNull("caname", caname);
		
		if(! casMap.containsKey(caname))
		{
			throw new IllegalArgumentException("Unknown CAConf " + caname);			
		}

		X509CmpRequestor requestor = cmpRequestorsMap.get(caname);
		CmpResultType result;
		try {
			result = generateCRL ? requestor.generateCRL() : requestor.downloadCurrentCRL();
		} catch (CmpRequestorException e) {
			throw new RAWorkerException(e);
		}
		
		if(result instanceof ErrorResultType)
		{
			throw createPKIErrorException((ErrorResultType) result);
		}
		else if(result instanceof CRLResultType)
		{
			CRLResultType downloadCRLResult = (CRLResultType) result;
			return downloadCRLResult.getCRL();
		}
		else
		{
			throw new RuntimeException("Unknown result type: " + result.getClass().getName());
		}
	}

	private String getCANameForProfile(String certProfile) 
	throws RAWorkerException
	{
		String caname = null;
		for(CAConf ca : casMap.values())
		{
			if(ca.getProfiles().contains(certProfile))
			{
				if(caname == null)
				{
					caname = ca.getName();
				}
				else
				{
					throw new RAWorkerException("Certificate profile " + certProfile + 
							" supported by more than one CA, please specify the CA name.");
				}
			}
		}
		
		return caname;
	}

	@Override
	protected java.security.cert.Certificate getCertificate(
			CMPCertificate cmpCert) throws CertificateException 
	{
		Certificate bcCert = cmpCert.getX509v3PKCert();
		return (bcCert == null) ? null : new X509CertificateObject(bcCert);
	}

    private static boolean isEmpty(String s)
    {
        return s == null || s.isEmpty();
    }

	public String getConfFile() {
		return confFile;
	}

	public void setConfFile(String confFile) {
		this.confFile = confFile;
	}

	@Override
	public Set<String> getCaNames()
	{
		return casMap.keySet();
	}

	@Override
	protected java.security.cert.Certificate getCACertficate(String caname) {
		CAConf caConf = casMap.get(caname);
		return caConf == null ? null : caConf.getCert();
	}

	@Override
	public byte[] envelope(CertReqMsg certReqMsg, String caName)
		throws RAWorkerException
	{
		ParamChecker.assertNotNull("request", certReqMsg);
		X509CmpRequestor cmpRequestor = getCmpRequestor(certReqMsg, caName);
		try {
			return cmpRequestor.envelope(certReqMsg).getEncoded();
		} catch (IOException e) {
			throw new RAWorkerException("IOException: " + e.getMessage(), e);
		} catch (CmpRequestorException e) {
			throw new RAWorkerException("CmpRequestorException: " + e.getMessage(), e);
		}
	}	
	
	private X509CmpRequestor getCmpRequestor(CertReqMsg request, String caName) 
	throws RAWorkerException
	{
		ParamChecker.assertNotNull("request", request);
		
		AttributeTypeAndValue[] regInfo = request.getRegInfo();
		
		CmpUtf8Pairs utf8Pairs = null;
		if (regInfo != null)
		{
			for(AttributeTypeAndValue atv : regInfo)
			{
				if(atv.getType().equals(CMPObjectIdentifiers.regInfo_utf8Pairs))
				{
					String atvValue = DERUTF8String.getInstance(atv.getValue()).getString();
					utf8Pairs = new CmpUtf8Pairs(atvValue);
					break;
				}
			}
		}
		
		String profileName = (utf8Pairs == null) ? null : utf8Pairs.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
		if(profileName == null)
		{
			throw new RAWorkerException("No CertProfile is specified in the request");
		}
		
		if(caName == null)
		{
			caName = getCANameForProfile(profileName);
			if(caName == null)
			{
				throw new RAWorkerException("CertProfile " + profileName + " is not supported by any CA"); 
			}
		}
		else
		{
			checkCertProfileSupportInCA(profileName, caName);
		}
		
		X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
		if(cmpRequestor == null)
		{
			throw new RAWorkerException("could not find CA named " + caName);
		}
		
		return cmpRequestor;
	}
	
}
