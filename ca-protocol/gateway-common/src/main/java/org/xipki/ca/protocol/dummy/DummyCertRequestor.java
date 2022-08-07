package org.xipki.ca.protocol.dummy;

import org.xipki.ca.protocol.Requestor;
import org.xipki.security.X509Cert;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class DummyCertRequestor implements Requestor {

  private X509Cert cert;

  static {
    System.err.println("DO NOT USE " + DummyCertRequestor.class.getName()
        + " IN THE PRODUCT ENVIRONMENT");
  }

  public DummyCertRequestor(X509Cert cert) {
    this.cert = cert;
  }

  @Override
  public String getName() {
    return cert.getCommonName();
  }

  @Override
  public char[] getPassword() {
    throw new UnsupportedOperationException("getPassword() unsupported");
  }

  @Override
  public byte[] getKeyId() {
    return cert.getSubjectKeyId();
  }

  @Override
  public X509Cert getCert() {
    return cert;
  }

  @Override
  public boolean authenticate(char[] password) {
    throw new UnsupportedOperationException("authenticate(byte[]) unsupported");
  }

  @Override
  public boolean authenticate(byte[] password) {
    throw new UnsupportedOperationException("authenticate(byte[]) unsupported");
  }

  @Override
  public boolean isCertprofilePermitted(String certprofile) {
    return true;
  }

  @Override
  public boolean isPermitted(int permission) {
    return true;
  }
}
