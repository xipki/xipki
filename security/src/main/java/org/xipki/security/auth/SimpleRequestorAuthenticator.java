// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.auth;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Simple Requestor Authenticator.
 * <pre>
 * {
 *   // optional
 *   "passwords": [
 *     {
 *       // required
 *       "user": "",
 *       // required, may be in clear text, obfuscated, or PBE-encrypted.
 *       "password": "",
 *       // required, valid values: ALL, CMP, EST, REST, SCEP
 *       "protocols":[],
 *       // required: valid values: ALL, ENROLL_CERT, REENROLL_CERT, GEN_KEYPAIR,
 *       //                         ENROLL_CROSS, UNSUSPEND_CERT, REVOKE_CERT
 *       "permissions":[],
 *       // required
 *       "caProfiles": [
 *         {
 *           // CA name or ALL for all CAs.
 *           "ca":"",
 *           // Certificate profile name or ALL for all profiles.
 *           "profiles":[]
 *         }
 *       ]
 *     }
 *   ],
 *   // optional
 *   "certs": [
 *     {
 *       // required
 *       "cert": "",
 *       // required, valid values: ALL, CMP, EST, REST, SCEP
 *       "protocols":[],
 *       // required: valid values: ALL, ENROLL_CERT, REENROLL_CERT, GEN_KEYPAIR,
 *       //                         ENROLL_CROSS, UNSUSPEND_CERT, REVOKE_CERT
 *       "permissions":[],
 *       // required
 *       "caProfiles": [
 *         {
 *           // CA name or ALL for all CAs.
 *           "ca":"",
 *           // Certificate profile name or ALL for all profiles.
 *           "profiles":[]
 *         }
 *       ]
 *     }
 *   ]
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SimpleRequestorAuthenticator implements RequestorAuthenticator {

  private static class CaProfiles {

    private final boolean allowAllCa;
    private final boolean allowAllProfiles;

    private final String ca;

    private final Set<String> profiles;

    public CaProfiles(String ca, Set<String> profiles) {
      this.ca = Args.notNull(ca, "ca").toUpperCase(Locale.ROOT);
      Args.notEmpty(profiles, "profiles");
      this.profiles = new HashSet<>(profiles.size());
      for (String m : profiles) {
        this.profiles.add(m.toUpperCase(Locale.ROOT));
      }

      this.allowAllCa = "ALL".equals(this.ca);
      this.allowAllProfiles = this.profiles.contains("ALL");
    }

    boolean isAllowed(String caName, String profile) {
      if (allowAllCa || ca.equals(caName.toUpperCase(Locale.ROOT))) {
        return allowAllProfiles || profiles.contains(profile.toUpperCase(Locale.ROOT));
      }

      return false;
    }

  }

  private static class AuthInfo {

    private final Set<Requestor.Permission> permissions;
    private final Set<CaProfiles> caProfilesSet;

    public AuthInfo(Set<Requestor.Permission> permissions, Set<CaProfiles> caProfilesSet) {
      this.permissions = Args.notEmpty(permissions, "permissions");
      this.caProfilesSet = Args.notEmpty(caProfilesSet, "caProfilesSet");
    }

    public boolean isCertprofilePermitted(String caName, String certprofile) {
      for (CaProfiles m : caProfilesSet) {
        if (m.isAllowed(caName, certprofile)) {
          return true;
        }
      }
      return false;
    }

    public boolean isPermitted(Requestor.Permission permission) {
      return permissions.contains(permission);
    }

  }

  private static class Password {

    private final Set<Requestor.Protocol> protocols;
    private final AuthInfo authInfo;

    private final String name;
    private final String user;
    private final byte[] keyId;
    private final char[] password;
    private final byte[] bytePassword;

    public Password(Set<Requestor.Protocol> protocols, AuthInfo authInfo,
                    String user, char[] password) {
      this.protocols = protocols;
      this.authInfo = Args.notNull(authInfo, "authInfo");
      this.user = Args.notBlank(user, "user");
      this.keyId = user.getBytes(StandardCharsets.UTF_8);
      this.password = Args.notNull(password, "password");
      this.bytePassword = new String(password).getBytes(StandardCharsets.UTF_8);
      this.name = "user-" + user;
    }

    boolean applyTo(Requestor.Protocol protocol, String user) {
      if (protocols != null && !protocols.contains(protocol)) {
        return false;
      }

      return this.user != null && this.user.equals(user);
    }

    boolean applyTo(Requestor.Protocol protocol, byte[] keyId) {
      if (protocols != null && !protocols.contains(protocol)) {
        return false;
      }

      return this.keyId != null && Arrays.equals(this.keyId, keyId);
    }

    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return authInfo.isCertprofilePermitted(caName, certprofile);
    }

    public boolean isPermitted(Requestor.Permission permission) {
      return authInfo.isPermitted(permission);
    }

  }

  private static class Cert {

    private final Set<Requestor.Protocol> protocols;
    private final AuthInfo authInfo;

    private final X509Cert cert;

    public Cert(Set<Requestor.Protocol> protocols, AuthInfo authInfo, X509Cert cert) {
      this.protocols = protocols;
      this.authInfo = Args.notNull(authInfo, "authInfo");
      this.cert = Args.notNull(cert, "cert");
    }

    boolean applyTo(Requestor.Protocol protocol, X509Cert cert) {
      if (protocols != null && !protocols.contains(protocol)) {
        return false;
      }

      return this.cert.equals(cert);
    }

    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return authInfo.isCertprofilePermitted(caName, certprofile);
    }

    public boolean isPermitted(Requestor.Permission permission) {
      return authInfo.isPermitted(permission);
    }

  }

  private static class MyPasswordRequestor implements
      Requestor.PasswordRequestor, Requestor.SimplePasswordRequestor {

    private final Password password;

    public MyPasswordRequestor(Password password) {
      this.password = Args.notNull(password, "password");
    }

    @Override
    public String name() {
      return password.name;
    }

    @Override
    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return password.isCertprofilePermitted(caName, certprofile);
    }

    @Override
    public boolean isPermitted(Permission permission) {
      return password.isPermitted(permission);
    }

    @Override
    public boolean authenticate(char[] password) {
      return Arrays.equals(this.password.password, password);
    }

    @Override
    public boolean authenticate(byte[] password) {
      return Arrays.equals(this.password.bytePassword, password);
    }

    boolean applyTo(Requestor.Protocol protocol, String user) {
      return password.applyTo(protocol, user);
    }

    boolean applyTo(Requestor.Protocol protocol, byte[] keyId) {
      return password.applyTo(protocol, keyId);
    }

    @Override
    public byte[] keyId() {
      return password.keyId;
    }

    @Override
    public char[] password() {
      return password.password;
    }
  }

  private static class MyCertRequestor implements Requestor.CertRequestor {

    private final String name;
    private final Cert cert;

    public MyCertRequestor(Cert cert) {
      this.cert = Args.notNull(cert, "cert");
      this.name = "cert-" + cert.cert.commonName();
    }

    @Override
    public String name() {
      return name;
    }

    @Override
    public boolean isCertprofilePermitted(String caName, String certprofile) {
      return cert.isCertprofilePermitted(caName, certprofile);
    }

    @Override
    public boolean isPermitted(Permission permission) {
      return cert.isPermitted(permission);
    }

    @Override
    public byte[] keyId() {
      return cert.cert.subjectKeyId();
    }

    @Override
    public X509Cert cert() {
      return cert.cert;
    }

  }

  private Set<MyPasswordRequestor> passwordRequestors;

  private Set<MyCertRequestor> certRequestors;

  public SimpleRequestorAuthenticator() {
  }

  @Override
  public void init(String conf) throws XiSecurityException {
    String confFile = StringUtil.isBlank(conf) ? "etc/simple-requestors.json" : conf;
    try {
      JsonMap root = JsonParser.parseMap( Path.of(IoUtil.expandFilepath(confFile, true)), true);

      Set<MyPasswordRequestor> passwordRequestors0 = null;
      JsonList list = root.getList("passwords");
      if (list != null) {
        List<JsonMap> jPasswords =  list.toMapList();
        passwordRequestors0 = new HashSet<>(jPasswords.size());

        for (JsonMap m : jPasswords) {
          String passwordHint = m.getNnString("password");
          char[] password = Passwords.resolvePassword(passwordHint);
          String user = m.getString("user");
          Password pwd = new Password(parseProtocols(m), parseAuthInfo(m), user, password);
          passwordRequestors0.add(new MyPasswordRequestor(pwd));
        }
      }

      Set<MyCertRequestor> certRequestors0 = null;
      list = root.getList("certs");
      if (list != null) {
        List<JsonMap> jCerts =  list.toMapList();
        certRequestors0 = new HashSet<>(jCerts.size());

        for (JsonMap m : jCerts) {
          FileOrBinary jCert = FileOrBinary.parse(m.getNnMap("cert"));
          X509Cert cert = (jCert.file() == null)
              ? new X509Cert((Certificate) null, jCert.binary())
              : X509Util.parseCert(IoUtil.expandFilepath(new File(jCert.file()), true));

          Cert crt = new Cert(parseProtocols(m), parseAuthInfo(m), cert);
          certRequestors0.add(new MyCertRequestor(crt));
        }
      }

      this.passwordRequestors = passwordRequestors0;
      this.certRequestors = certRequestors0;
    } catch (CodecException | PasswordResolverException | IOException | CertificateException e) {
      throw new XiSecurityException(e.getMessage(), e);
    }
  }

  private static AuthInfo parseAuthInfo(JsonMap map) throws CodecException {
    List<String> strs = map.getNnStringList("permissions");
    Set<Requestor.Permission> permissions = new HashSet<>(strs.size());
    if (strs.contains("ALL") || strs.contains("all")) {
      permissions.addAll(Arrays.asList(Requestor.Permission.values()));
    } else {
      for (String m : strs) {
        permissions.add(Requestor.Permission.of(m));
      }
    }

    JsonList list = map.getNnList("caProfiles");
    Set<CaProfiles> caProfilesList = new HashSet<>(list.size());
    for (JsonMap m : list.toMapList()) {
      String ca = m.getNnString("ca");
      Set<String> profiles = m.getNnStringSet("profiles");
      caProfilesList.add(new CaProfiles(ca, profiles));
    }

    return new AuthInfo(permissions, caProfilesList);
  }

  private static Set<Requestor.Protocol> parseProtocols(JsonMap map) throws CodecException {
    List<String> protocols = map.getNnStringList("protocols");
    Set<Requestor.Protocol> ret = new HashSet<>(protocols.size());
    if (protocols.contains("ALL") || protocols.contains("all")) {
      ret.addAll(Arrays.asList(Requestor.Protocol.values()));
    } else {
      for (String m : protocols) {
        ret.add(Requestor.Protocol.of(m));
      }
    }
    return ret;
  }

  @Override
  public Requestor.SimplePasswordRequestor getSimplePasswordRequestorByKeyId(
      Requestor.Protocol protocol, byte[] keyId) {
    if (passwordRequestors != null) {
      for (MyPasswordRequestor m : passwordRequestors) {
        if (m.applyTo(protocol, keyId)) {
          return m;
        }
      }
    }
    return null;
  }

  @Override
  public Requestor.PasswordRequestor getPasswordRequestorByUser(
      Requestor.Protocol protocol, String user) {
    if (passwordRequestors != null) {
      for (MyPasswordRequestor m : passwordRequestors) {
        if (m.applyTo(protocol, user)) {
          return m;
        }
      }
    }
    return null;
  }

  @Override
  public Requestor.CertRequestor getCertRequestor(Requestor.Protocol protocol, X509Cert cert) {
    if (certRequestors != null) {
      for (MyCertRequestor m : certRequestors) {
        if (m.cert.applyTo(protocol, cert)) {
          return m;
        }
      }
    }

    return null;
  }

}
