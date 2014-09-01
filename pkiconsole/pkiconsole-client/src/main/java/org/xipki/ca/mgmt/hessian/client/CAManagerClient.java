package org.xipki.ca.mgmt.hessian.client;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.common.CAMgmtException;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.CmpControl;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.CrlSignerEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.ParamChecker;

import com.caucho.hessian.client.HessianProxyFactory;

public class CAManagerClient implements CAManager
{
	
	@SuppressWarnings("unused")
	private final Logger LOG = LoggerFactory.getLogger(getClass());
	private final CAManager client;

	public CAManagerClient(
			String serverURL) 
			throws Exception
	{
		ParamChecker.assertNotNull("serverURL", serverURL);
		
		HessianProxyFactory factory = new HessianProxyFactory();
		factory.setHessian2Request(true);
		factory.setHessian2Reply(true);
		
		this.client = (CAManager) factory.create(
				CAManager.class, serverURL);	    
	}

	@Override
	public CASystemStatus getCASystemStatus() {
		return client.getCASystemStatus();
	}

	@Override
	public boolean unlockCA() {
		return client.unlockCA();
	}

	@Override
	public void publishRootCA(String caName, String certprofile)
	throws CAMgmtException {
		client.publishRootCA(caName, certprofile);		
	}

	@Override
	public boolean republishCertificates(String caName, List<String> publisherNames)
	throws CAMgmtException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean clearPublishQueue(String caName, List<String> publisherNames)
	throws CAMgmtException
	{
		return client.clearPublishQueue(caName, publisherNames);
	}

	@Override
	public void removeCA(String caName)
	throws CAMgmtException {
		client.removeCA(caName);
	}

	@Override
	public boolean restartCaSystem()
	{
		return client.restartCaSystem();
	}

	@Override
	public void addCaAlias(String aliasName, String caName)
	throws CAMgmtException
	{
		client.addCaAlias(aliasName, caName);
	}

	@Override
	public void removeCaAlias(String aliasName)
	throws CAMgmtException {
		client.removeCaAlias(aliasName);
	}

	@Override
	public String getAliasName(String caName) {
		return client.getAliasName(caName);
	}

	@Override
	public String getCaName(String aliasName) {
		return client.getCaName(aliasName);
	}

	@Override
	public Set<String> getCaAliasNames() {
		return client.getCaAliasNames();
	}

	@Override
	public Set<String> getCertProfileNames() {
		return client.getCertProfileNames();
	}

	@Override
	public Set<String> getPublisherNames() {
		return client.getPublisherNames();
	}

	@Override
	public Set<String> getCmpRequestorNames() {
		return client.getCmpRequestorNames();
	}

	@Override
	public Set<String> getCrlSignerNames() {
		return client.getCrlSignerNames();
	}

	@Override
	public Set<String> getCANames() {
		return client.getCANames();
	}

	@Override
	public void addCA(CAEntry newCaDbEntry)
	throws CAMgmtException {
		client.addCA(newCaDbEntry);		
	}

	@Override
	public CAEntry getCA(String caName)
	{
		return client.getCA(caName);
	}

	@Override
	public void changeCA(String name, CAStatus status, Long nextSerial,
			X509Certificate cert, Set<String> crl_uris,
			Set<String> delta_crl_uris, Set<String> ocsp_uris,
			Integer max_validity, String signer_type, String signer_conf,
			String crlsigner_name, DuplicationMode duplicate_key,
			DuplicationMode duplicate_subject, Set<Permission> permissions,
			Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
	throws CAMgmtException
	{
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCertProfileFromCA(String profileName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addCertProfileToCA(String profileName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removePublisherFromCA(String publisherName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addPublisherToCA(String publisherName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Set<String> getCertProfilesForCA(String caName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CmpRequestorEntry getCmpRequestor(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void addCmpRequestor(CmpRequestorEntry dbEntry)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCmpRequestor(String requestorName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeCmpRequestor(String name, String cert)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCmpRequestorFromCA(String requestorName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public CertProfileEntry getCertProfile(String profileName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removeCertProfile(String profileName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeCertProfile(String name, String type, String conf)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addCertProfile(CertProfileEntry dbEntry) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setCmpResponder(CmpResponderEntry dbEntry)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCmpResponder() throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeCmpResponder(String type, String conf, String cert)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public CmpResponderEntry getCmpResponder() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void addCrlSigner(CrlSignerEntry dbEntry) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCrlSigner(String crlSignerName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeCrlSigner(String name, String signer_type,
			String signer_conf, String signer_cert, String crlControl)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public CrlSignerEntry getCrlSigner(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setCrlSignerInCA(String crlSignerName, String caName)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addPublisher(PublisherEntry dbEntry) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public List<PublisherEntry> getPublishersForCA(String caName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PublisherEntry getPublisher(String publisherName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removePublisher(String publisherName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changePublisher(String name, String type, String conf)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public CmpControl getCmpControl() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setCmpControl(CmpControl dbEntry) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCmpControl() throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeCmpControl(Boolean requireConfirmCert,
			Boolean requireMessageTime, Integer messageTimeBias,
			Integer confirmWaitTime, Boolean sendCaCert,
			Boolean sendResponderCert) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Set<String> getEnvParamNames() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getEnvParam(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void addEnvParam(String name, String value) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeEnvParam(String envParamName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changeEnvParam(String name, String value)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void revokeCa(String caName, CertRevocationInfo revocationInfo)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unrevokeCa(String caName) throws CAMgmtException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean revokeCertificate(String caName, BigInteger serialNumber,
			CRLReason reason, Date invalidityTime) throws CAMgmtException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean unrevokeCertificate(String caName, BigInteger serialNumber)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean removeCertificate(String caName, BigInteger serialNumber)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public X509Certificate generateCertificate(String caName,
			String profileName, String user, byte[] encodedPkcs10Request)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate generateSelfSignedCA(String name,
			String certprofileName, String subject, CAStatus status,
			long nextSerial, List<String> crl_uris,
			List<String> delta_crl_uris, List<String> ocsp_uris,
			int max_validity, String signer_type, String signer_conf,
			String crlsigner_name, DuplicationMode duplicate_key,
			DuplicationMode duplicate_subject, Set<Permission> permissions,
			int numCrls, int expirationPeriod, ValidityMode validityMode)
			throws CAMgmtException {
		// TODO Auto-generated method stub
		return null;
	}
		

}
