// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dummy;

import org.xipki.ca.gateway.Requestor;
import org.xipki.ca.gateway.RequestorAuthenticator;
import org.xipki.security.X509Cert;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class DummyRequestorAuthenticator implements RequestorAuthenticator {

  static {
    System.err.println("DO NOT USE " + DummyRequestorAuthenticator.class.getName() + " IN THE PRODUCT ENVIRONMENT");
  }

  @Override
  public Requestor.SimplePasswordRequestor getSimplePasswordRequestorByKeyId(byte[] keyId) {
    return DummySimpleasswordRequestor.ofKeyId(keyId);
  }

  @Override
  public Requestor.PasswordRequestor getPasswordRequestorByUser(String user) {
    return DummyPasswordRequestor.ofUser(user);
  }

  @Override
  public Requestor.CertRequestor getCertRequestor(X509Cert cert) {
    return new DummyCertRequestor(cert);
  }

  private static class DummyCertRequestor implements Requestor.CertRequestor {

    private final X509Cert cert;

    public DummyCertRequestor(X509Cert cert) {
      this.cert = cert;
    }

    @Override
    public String getName() {
      return cert.getCommonName();
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
    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return true;
    }

    @Override
    public boolean isPermitted(int permission) {
      return true;
    }
  }

  private static class DummyPasswordRequestor implements Requestor.PasswordRequestor {

    private final String user;

    private final char[] password;

    protected final static Map<String, char[]> passwordMap = new HashMap<>();

    static {
      passwordMap.put("user1", "password1".toCharArray());
      passwordMap.put("user2", "password2".toCharArray());
    }

    private DummyPasswordRequestor(String user, char[] password) {
      this.user = user;
      this.password = password;
    }

    public static DummyPasswordRequestor ofUser(String user) {
      char[] password = passwordMap.get(user);
      if (password == null) {
        return null;
      }
      return new DummyPasswordRequestor(user, password);
    }

    public static DummyPasswordRequestor ofKeyId(byte[] keyId) {
      String user = new String(keyId, StandardCharsets.UTF_8);
      char[] password = passwordMap.get(user);
      if (password == null) {
        return null;
      }
      return new DummyPasswordRequestor(user, password);
    }

    @Override
    public String getName() {
      return "passwordrequestor-" + user;
    }

    @Override
    public boolean authenticate(char[] password) {
      return Arrays.equals(this.password, password);
    }

    @Override
    public boolean authenticate(byte[] password) {
      char[] charPassword = password == null ? null : new String(password, StandardCharsets.UTF_8).toCharArray();
      return authenticate(charPassword);
    }

    @Override
    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return true;
    }

    @Override
    public boolean isPermitted(int permission) {
      return true;
    }
  }

  private static class DummySimpleasswordRequestor implements Requestor.SimplePasswordRequestor {

    private final String user;

    private final char[] password;

    private final byte[] keyId;

    protected final static Map<String, char[]> passwordMap = new HashMap<>();

    static {
      passwordMap.put("user1", "password1".toCharArray());
      passwordMap.put("user2", "password2".toCharArray());
    }

    private DummySimpleasswordRequestor(String user, char[] password) {
      this.user = user;
      this.password = password;
      this.keyId = user.getBytes(StandardCharsets.UTF_8);
    }

    public static DummySimpleasswordRequestor ofKeyId(byte[] keyId) {
      String user = new String(keyId, StandardCharsets.UTF_8);
      char[] password = passwordMap.get(user);
      if (password == null) {
        return null;
      }
      return new DummySimpleasswordRequestor(user, password);
    }

    @Override
    public String getName() {
      return "extendedpasswordrequestor-" + user;
    }

    @Override
    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return true;
    }

    @Override
    public boolean isPermitted(int permissions) {
      return true;
    }

    @Override
    public byte[] getKeyId() {
      return keyId;
    }

    @Override
    public char[] getPassword() {
      return password;
    }

  }

}
