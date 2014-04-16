package org.xipki.ca.api.profile;


public abstract class AbstractEECertProfile extends AbstractCertProfile 
{
	@Override
	public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier() {
		return ExtensionOccurrence.CRITICAL_REQUIRED;
	}

	@Override
	protected boolean isCa() {
		return false;
	}

	@Override
	protected Integer getPathLenBasicConstraint() {
		return null;
	}

}
