// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.util;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Util {

  public static String getCommonName(X500Principal name) {
    return getRdnValue(name, "CN");
  }

  public static String getRdnValue(X500Principal name, String rdnType) {
    String dn = name.getName();
    LdapName ldapDN;
    try {
      ldapDN = new LdapName(dn);
    } catch (InvalidNameException ex) {
      throw new IllegalArgumentException("invalid LdapName", ex);
    }
    for(Rdn rdn: ldapDN.getRdns()) {
      if (rdn.getType().equalsIgnoreCase(rdnType)) {
        Object obj = rdn.getValue();
        if (obj instanceof String) {
          return (String) obj;
        } else {
          return obj.toString();
        }
      }
    }

    return null;
  }

}
