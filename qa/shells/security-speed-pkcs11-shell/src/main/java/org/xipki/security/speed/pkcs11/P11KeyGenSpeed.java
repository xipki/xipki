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

package org.xipki.security.speed.pkcs11;

import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.qa.BenchmarkExecutor;
import org.xipki.security.pkcs11.P11NewKeyControl;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11KeyGenSpeed extends BenchmarkExecutor {

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          genKeypair();
          account(1, 0);
        } catch (Exception ex) {
          account(1, 1);
        }
      }
    }

  } // class Testor

  protected final P11Slot slot;

  private byte[] id;

  private AtomicLong idx = new AtomicLong(System.currentTimeMillis());

  public P11KeyGenSpeed(P11Slot slot, byte[] id, String description) {
    super(description);
    this.slot = ParamUtil.requireNonNull("slot", slot);
    this.id = id;
  }

  protected abstract void genKeypair() throws Exception;

  protected P11NewKeyControl getControl() {
    P11NewKeyControl control = new P11NewKeyControl(id, "speed-" + idx.getAndIncrement());
    control.setExtractable(true);
    return control;
  }

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

}
