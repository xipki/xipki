/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security.speed.p12;

import java.security.SecureRandom;

import org.xipki.common.LoadExecutor;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.SecurityFactory;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12KeyGenLoadTest extends LoadExecutor {

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          generateKeypair(securityFactory.getRandom4Key());
          account(1, 0);
        } catch (Exception ex) {
          account(1, 1);
        }
      }
    }

  } // class Testor

  private final SecurityFactory securityFactory;

  public P12KeyGenLoadTest(String description, SecurityFactory securityFactory) {
    super(description);
    this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
  }

  protected abstract void generateKeypair(SecureRandom random) throws Exception;

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

}
