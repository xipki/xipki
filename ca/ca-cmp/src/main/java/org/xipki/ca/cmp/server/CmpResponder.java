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

package org.xipki.ca.cmp.server;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.ProtectionResult;
import org.xipki.ca.cmp.ProtectionVerificationResult;
import org.xipki.ca.common.CertBasedRequestorInfo;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.ParamChecker;

public abstract class CmpResponder {
	private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

	private final SecureRandom random = new SecureRandom();
	protected final ConcurrentContentSigner responder;
	protected final GeneralName sender;
	
	private final Map<GeneralName, CertBasedRequestorInfo> authorizatedRequestors = 
			new HashMap<GeneralName, CertBasedRequestorInfo>();
	
	private int signserviceTimeout = 5000; // 5 seconds
	
	protected final SecurityFactory securityFactory;
	
	
	protected abstract boolean isCAInService();
	
	/**
	 * @return never returns {@code null}.
	 */
	protected abstract CmpControl getCmpControl();
	
	protected abstract PKIMessage intern_processPKIMessage(RequestorInfo requestor, String user,
			ASN1OctetString transactionId, GeneralPKIMessage pkiMessage);
	
	protected CmpResponder(ConcurrentContentSigner responder, SecurityFactory securityFactory)
	{
		ParamChecker.assertNotNull("responder", responder);
		ParamChecker.assertNotNull("securityFactory", securityFactory);
		
		this.responder = responder;
		this.securityFactory = securityFactory;
		X500Name x500Name = X500Name.getInstance(responder.getCertificate().getSubjectX500Principal().getEncoded());
		this.sender = new GeneralName(x500Name);
	}
	
	public void setSignserviceTimeout(int signserviceTimeout)
	{
		if(signserviceTimeout < 0)
		{
			throw new IllegalArgumentException("negative signserviceTimeout is not allowed: " + signserviceTimeout);
		}
		this.signserviceTimeout = signserviceTimeout;
	}

	public PKIMessage processPKIMessage(PKIMessage pkiMessage)
	{
		GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);
		
		PKIHeader reqHeader = message.getHeader();
		ASN1OctetString tid = reqHeader.getTransactionID();
	
		if(isCAInService() == false)
		{
			return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.systemUnavail, "CA is out of service");
		}
		
		checkRequestRecipient(reqHeader);
		
		if(tid == null)
		{
			byte[] randomBytes = randomTransactionId();
			tid = new DEROctetString(randomBytes);
		}
		String tidStr = Hex.toHexString(tid.getOctets());	
		
		CmpControl cmpControl = getCmpControl();

		Integer failureCode = null;
		String statusText = null;			

		DERGeneralizedTime messageTime = reqHeader.getMessageTime();
		if(messageTime == null)
		{
			failureCode = PKIFailureInfo.missingTimeStamp;
		}
		else
		{
			try {
				long messageTimeBias = cmpControl.getMessageTimeBias();
				if(messageTimeBias < 0)
				{
					messageTimeBias *= -1;
				}
				messageTimeBias *= 1000; // second to millisecond
				
				long msgTimeMs = messageTime.getDate().getTime();
				long currentTimeMs = System.currentTimeMillis();
				long bias = msgTimeMs - currentTimeMs;
				if(bias > messageTimeBias)
				{
					failureCode = PKIFailureInfo.badTime;
					statusText = "message time is in the future";
				}
				else if(bias * -1 > messageTimeBias)
				{
					failureCode = PKIFailureInfo.badTime;
					statusText = "message too old";
				}
			} catch (ParseException e) {
				failureCode = PKIFailureInfo.badRequest;
				statusText = "invalid message time format";
			}
		}
			
		if(failureCode != null)
		{
			return buildErrorPkiMessage(tid, reqHeader, failureCode, statusText);
		}
		
		boolean isProtected = message.hasProtection();
		ProtectionVerificationResult verificationResult = null;
		String errorStatus = null;
		
		if(isProtected)
		{			
			try {
				verificationResult = verifyProtection(tidStr, message);
				ProtectionResult pr = verificationResult.getProtectionResult();
				if(pr != ProtectionResult.VALID)
				{
					errorStatus = pr == ProtectionResult.NOT_SIGNATURE_BASED ? 
							"Request has invalid signature based protection" :
							"Request has protection but is not signature based";
				}
			} catch (Exception e) {
				LOG.error("tid=" + tidStr + ": error while verifying the signature", e);
				errorStatus = "Request has invalid signature based protection";
			}
		}
		else
		{
			errorStatus = "Request has no protection";
		}
			
		if(errorStatus != null)
		{
			return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus);
		}
		
		CertBasedRequestorInfo requestor = verificationResult == null ? null :
			(CertBasedRequestorInfo) verificationResult.getRequestor();
		PKIMessage resp = intern_processPKIMessage(requestor, null, tid, message);
		resp = addProtection(resp);

		return resp;
	}
	
	protected byte[] randomTransactionId()
	{
		byte[] b = new byte[10];
		synchronized (random) {
			random.nextBytes(b);
		}
		return  b;
	}	
	
	private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage)
	throws CMPException, InvalidKeyException, OperatorCreationException
	{
		ProtectedPKIMessage pMsg = new ProtectedPKIMessage(pkiMessage);
		
		if(pMsg.hasPasswordBasedMacProtection())
		{
			LOG.warn("NOT_SIGNAUTRE_BASED: " + pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId()); 
			return new ProtectionVerificationResult(null, ProtectionResult.NOT_SIGNATURE_BASED);
		}
		
		PKIHeader h = pMsg.getHeader();
		CertBasedRequestorInfo requestor = getRequestor(h);
		if(requestor == null)			
		{
			LOG.warn("tid={}: not authorized requestor {}", tid, h.getSender());
			return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
		}
		
		ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(
				requestor.getCertificate().getCert());
		if(verifierProvider == null)
		{
			LOG.warn("tid={}: not authorized requestor {}", tid, h.getSender());
			return new ProtectionVerificationResult(requestor, ProtectionResult.SENDER_NOT_AUTHORIZED);
		}
		
		boolean signatureValid = pMsg.verify(verifierProvider);
		return new ProtectionVerificationResult(requestor,
				signatureValid ? ProtectionResult.VALID : ProtectionResult.INVALID);
	}

	private PKIMessage addProtection(PKIMessage pkiMessage)
	{
		try {
			return CmpUtil.addProtection(pkiMessage, responder, sender, signserviceTimeout);
		} catch (Exception e) {
			LOG.error("error while add protection to the PKI message: {}", e.getMessage());
			LOG.debug("error while add protection to the PKI message", e);
			
			PKIStatusInfo status = generateCmpRejectionStatus(
					PKIFailureInfo.systemFailure, "could not sign the PKIMessage");
			PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status));
			
			return new PKIMessage(pkiMessage.getHeader(), body);
		}
	}
	
	
	private void checkRequestRecipient(PKIHeader reqHeader)
	{
		ASN1OctetString tid = reqHeader.getTransactionID();
		GeneralName recipient = reqHeader.getRecipient();
		
		if(!sender.equals(recipient))
		{
			LOG.warn("tid={}: Unknown Recipient '{}'", tid, recipient);
		}		
	}
	
	protected PKIMessage buildErrorPkiMessage(ASN1OctetString tid,
			PKIHeader requestHeader, 
			int failureCode,
			String statusText)
	{
		GeneralName respRecipient = requestHeader.getSender();		
		
		PKIHeaderBuilder respHeader = new PKIHeaderBuilder(requestHeader.getPvno().getValue().intValue(),
				sender, respRecipient);
		respHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
		if(tid != null)
		{
			respHeader.setTransactionID(tid);
		}
		
		PKIStatusInfo status = generateCmpRejectionStatus(failureCode, statusText);
		ErrorMsgContent error = new ErrorMsgContent(status);
		PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, error);
		
		return new PKIMessage(respHeader.build(), body);		
	}
	
	private CertBasedRequestorInfo getRequestor(PKIHeader reqHeader)
	{
		GeneralName requestSender = reqHeader.getSender();
		CertBasedRequestorInfo requestor = authorizatedRequestors.get(requestSender);
		if(requestor != null)
		{
			ASN1OctetString kid = reqHeader.getSenderKID();
			if(kid != null)
			{
				// TODO : check the kid
			}
		}
		
		return requestor;
	}
	
	
	protected PKIStatusInfo generateCmpRejectionStatus(
			Integer info, String errorMessage)
	{
		PKIFreeText statusMessage = errorMessage == null ? 
				null :
				new PKIFreeText(errorMessage);
		
		PKIFailureInfo failureInfo = info == null ?
				null :
				new PKIFailureInfo(info);
		
		return new PKIStatusInfo(PKIStatus.rejection, statusMessage, failureInfo);		
	}

	public void addAutorizatedRequestor(CertBasedRequestorInfo requestor)
	{
		X500Name subject = X500Name.getInstance(
				requestor.getCertificate().getCert().getSubjectX500Principal().getEncoded());
		GeneralName name = new GeneralName(subject);		
		this.authorizatedRequestors.put(name, requestor);
	}

	public X500Name getResponderName()
	{
		return sender == null ? null : (X500Name) sender.getName();
	}
	
	public X509Certificate getResponderCert()
	{
		return responder == null ? null : responder.getCertificate();
	}

}
