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

package org.xipki.dbtool;

import org.xipki.util.ParamUtil;

import liquibase.changelog.ChangeSet;
import liquibase.changelog.DatabaseChangeLog;
import liquibase.logging.LogLevel;
import liquibase.logging.Logger;

/**
 * Logger wrapper.
 *
 * @author Lijun Liao
 */

class MyLogger implements Logger {

  private static final String MSG_NOCASCADE = "Database does not support drop with cascade";

  private Logger underlying;

  public MyLogger(Logger underlying) {
    this.underlying = ParamUtil.requireNonNull("underlying", underlying);
  }

  @Override
  public int getPriority() {
    return underlying.getPriority();
  }

  @Override
  public void setName(String name) {
    underlying.setName(name);
  }

  @Override
  public void setLogLevel(String level) {
    underlying.setLogLevel(level);
  }

  @Override
  public void setLogLevel(LogLevel level) {
    underlying.setLogLevel(level);
  }

  @Override
  public void setLogLevel(String logLevel, String logFile) {
    underlying.setLogLevel(logLevel, logFile);
  }

  @Override
  public void closeLogFile() {
    underlying.closeLogFile();

  }

  @Override
  public void severe(String message) {
    underlying.severe(message);
  }

  @Override
  public void severe(String message, Throwable ex) {
    underlying.severe(message, ex);
  }

  @Override
  public void warning(String message) {
    if (MSG_NOCASCADE.equalsIgnoreCase(message)) {
      debug(message);
    } else {
      underlying.warning(message);
    }
  }

  @Override
  public void warning(String message, Throwable ex) {
    if (MSG_NOCASCADE.equalsIgnoreCase(message)) {
      debug(message, ex);
    } else {
      underlying.warning(message, ex);
    }
  }

  @Override
  public void info(String message) {
    underlying.info(message);
  }

  @Override
  public void info(String message, Throwable ex) {
    underlying.info(message, ex);
  }

  @Override
  public void debug(String message) {
    underlying.debug(message);
  }

  @Override
  public void debug(String message, Throwable ex) {
    underlying.debug(message, ex);
  }

  @Override
  public LogLevel getLogLevel() {
    return underlying.getLogLevel();
  }

  @Override
  public void setChangeLog(DatabaseChangeLog databaseChangeLog) {
    underlying.setChangeLog(databaseChangeLog);
  }

  @Override
  public void setChangeSet(ChangeSet changeSet) {
    underlying.setChangeSet(changeSet);
  }

}
