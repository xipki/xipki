// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.xipki.util.exception.InvalidConfException;

import java.util.Collection;

/**
 * Configuration that can be validated.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class ValidableConf {

  protected static void validate(ValidableConf aConf, ValidableConf... extraConfs) throws InvalidConfException {
    if (aConf != null) {
      aConf.validate();
    }

    for (ValidableConf conf : extraConfs) {
      if (conf != null) {
        conf.validate();
      }
    }
  }

  @SafeVarargs
  protected static void validate(Collection<? extends ValidableConf> aConfList,
                                 Collection<? extends ValidableConf>... confLists) throws InvalidConfException {
    if (aConfList != null) {
      for (ValidableConf conf : aConfList) {
        conf.validate();
      }
    }

    for (Collection<? extends ValidableConf> confList : confLists) {
      if (confList != null) {
        for (ValidableConf conf : confList) {
          conf.validate();
        }
      }
    }
  }

  protected static void notBlank(String value, String name) throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
    if (value.isEmpty()) {
      throw new InvalidConfException(name + " may not be empty");
    }
  }

  protected static void notEmpty(Collection<?> value, String name) throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
    if (value.isEmpty()) {
      throw new InvalidConfException(name + " may not be empty");
    }
  }

  protected static void notNull(Object value, String name) throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
  }

  protected static void _null(Object value, String name) throws InvalidConfException {
    if (value != null) {
      throw new InvalidConfException(name + " may not be non-null");
    }
  }

  protected void exactOne(Object value1, String name1, Object value2, String name2)
      throws InvalidConfException {
    if (value1 == null && value2 == null) {
      throw new InvalidConfException(name1 + " and " + name2 + " may not be both null");
    } else if (value1 != null && value2 != null) {
      throw new InvalidConfException(name1 + " and " + name2 + " may not be both non-null");
    }
  }

  public abstract void validate() throws InvalidConfException;

}
