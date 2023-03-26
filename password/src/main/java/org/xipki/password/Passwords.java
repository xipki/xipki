// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * Utility class to initialize {@link PasswordResolver}.
 *
 * @author Lijun Liao (xipki)
 */

public class Passwords {

  public static class PasswordConf {

    public static final String dflt_masterPasswordCallback = "PBE-GUI quorum=1,tries=3";

    private String masterPasswordCallback;

    public static final PasswordConf DEFAULT;

    static {
      DEFAULT = new PasswordConf();
    }

    /**
     * list of classes that implement org.xipki.password.SinglePasswordResolver
     */
    private List<String> singlePasswordResolvers;

    public String getMasterPasswordCallback() {
      return Args.isBlank(masterPasswordCallback) ? dflt_masterPasswordCallback : masterPasswordCallback;
    }

    public void setMasterPasswordCallback(String masterPasswordCallback) {
      this.masterPasswordCallback = masterPasswordCallback;
    }

    public List<String> getSinglePasswordResolvers() {
      return singlePasswordResolvers;
    }

    public void setSinglePasswordResolvers(List<String> singlePasswordResolvers) {
      this.singlePasswordResolvers = singlePasswordResolvers;
    }

  } // class PasswordConf

  private PasswordResolverImpl passwordResolver;

  public void init() throws PasswordResolverException {
    init(null);
  }

  public void init(PasswordConf conf) throws PasswordResolverException {
    passwordResolver = new PasswordResolverImpl();
    if (conf == null) {
      conf = PasswordConf.DEFAULT;
    }

    passwordResolver.setMasterPasswordCallback(conf.getMasterPasswordCallback());
    passwordResolver.init();

    List<String> singlePasswordResolvers = conf.getSinglePasswordResolvers();
    // register additional SinglePasswordResolvers
    if (Args.isNotEmpty(singlePasswordResolvers)) {
      for (String className : singlePasswordResolvers) {
        try {
          Class<?> clazz = Class.forName(className);
          SinglePasswordResolver resolver = (SinglePasswordResolver) clazz.getDeclaredConstructor().newInstance();
          passwordResolver.registResolver(resolver);
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException ex) {
          throw new PasswordResolverException("error caught while initializing SinglePasswordResolver "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }
  } // method init

  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

}
