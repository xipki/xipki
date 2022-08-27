/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.password;

import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * Utility class to initialize {@link PasswordResolver}.
 *
 * @author Lijun Liao
 */

public class Passwords {

  public static class PasswordConf extends ValidatableConf {

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
      return StringUtil.isBlank(masterPasswordCallback) ? dflt_masterPasswordCallback : masterPasswordCallback;
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

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class PasswordConf

  private PasswordResolverImpl passwordResolver;

  public void init() throws IOException, InvalidConfException {
    init(null);
  }

  public void init(PasswordConf conf) throws IOException, InvalidConfException {
    passwordResolver = new PasswordResolverImpl();
    if (conf == null) {
      conf = PasswordConf.DEFAULT;
    }

    passwordResolver.setMasterPasswordCallback(conf.getMasterPasswordCallback());
    passwordResolver.init();

    List<String> singlePasswordResolvers = conf.getSinglePasswordResolvers();
    // register additional SinglePasswordResolvers
    if (CollectionUtil.isNotEmpty(singlePasswordResolvers)) {
      for (String className : singlePasswordResolvers) {
        try {
          Class<?> clazz = Class.forName(className);
          SinglePasswordResolver resolver = (SinglePasswordResolver) clazz.getDeclaredConstructor().newInstance();
          passwordResolver.registResolver(resolver);
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException ex) {
          throw new InvalidConfException("error caught while initializing SinglePasswordResolver "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }
  } // method init

  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

}
