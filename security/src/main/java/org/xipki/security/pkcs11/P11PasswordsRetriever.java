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

package org.xipki.security.pkcs11;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11PasswordsRetriever {

  private static final class SingleRetriever {

    private final Set<P11SlotIdFilter> slots;

    private final List<String> passwords;

    private SingleRetriever(Set<P11SlotIdFilter> slots, List<String> passwords) {
      this.slots = slots;
      this.passwords = CollectionUtil.isEmpty(passwords) ? null : passwords;
    }

    public boolean match(P11SlotIdentifier slot) {
      if (slots == null) {
        return true;
      }
      for (P11SlotIdFilter m : slots) {
        if (m.match(slot)) {
          return true;
        }
      }

      return false;
    }

    public List<char[]> getPasswords(PasswordResolver passwordResolver)
            throws PasswordResolverException {
      if (passwords == null) {
        return null;
      }

      List<char[]> ret = new ArrayList<char[]>(passwords.size());
      for (String password : passwords) {
        if (passwordResolver == null) {
          ret.add(password.toCharArray());
        } else {
          ret.add(passwordResolver.resolvePassword(password));
        }
      }

      return ret;
    }

  } // class SingleRetriever

  private final List<SingleRetriever> singleRetrievers;
  private PasswordResolver passwordResolver;

  P11PasswordsRetriever() {
    singleRetrievers = new LinkedList<>();
  }

  void addPasswordEntry(Set<P11SlotIdFilter> slots, List<String> passwords) {
    singleRetrievers.add(new SingleRetriever(slots, passwords));
  }

  public List<char[]> getPassword(P11SlotIdentifier slotId) throws PasswordResolverException {
    Args.notNull(slotId, "slotId");
    if (CollectionUtil.isEmpty(singleRetrievers)) {
      return null;
    }

    for (SingleRetriever sr : singleRetrievers) {
      if (sr.match(slotId)) {
        return sr.getPasswords(passwordResolver);
      }
    }

    return null;
  }

  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

}
