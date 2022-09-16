/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.io.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * The No-Operation audit service. The events will be ignored.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class NoopAuditService implements AuditService {

  public NoopAuditService() {
  }

  @Override
  public void init(String conf) {
  }

  @Override
  public void init(String conf, PasswordResolver passwordResolver)
      throws PasswordResolverException {
  }

  @Override
  public void logEvent(AuditEvent event) {
  }

  @Override
  public void logEvent(PciAuditEvent event) {
  }

  @Override
  public void close() throws Exception {
  }

}
