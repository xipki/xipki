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

package org.xipki.util;

import org.xipki.util.exception.InvalidConfException;

import java.util.Collection;

/**
 * Configuration that can be validated.
 *
 * @author Lijun Liao
 */

public abstract class ValidatableConf {

  protected static void validate(ValidatableConf conf) throws InvalidConfException {
    if (conf != null) {
      conf.validate();
    }
  }

  protected static void validate(Collection<? extends ValidatableConf> conf)
      throws InvalidConfException {
    if (conf != null) {
      for (ValidatableConf m : conf) {
        m.validate();
      }
    }
  }

  protected static void notBlank(String value, String name)
      throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
    if (value.isEmpty()) {
      throw new InvalidConfException(name + " may not be empty");
    }
  }

  protected static void notEmpty(Collection<?> value, String name)
      throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
    if (value.isEmpty()) {
      throw new InvalidConfException(name + " may not be empty");
    }
  }

  protected static void notNull(Object value, String name)
      throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException(name + " may not be null");
    }
  }

  protected static void _null(Object value, String name)
      throws InvalidConfException {
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

  public abstract void validate()
      throws InvalidConfException;

}
