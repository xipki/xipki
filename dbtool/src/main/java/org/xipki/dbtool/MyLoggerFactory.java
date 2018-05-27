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

import java.util.HashMap;
import java.util.Map;

import liquibase.logging.LogFactory;
import liquibase.logging.Logger;

/**
 * Logger factory.
 *
 * @author Lijun Liao
 */

class MyLoggerFactory extends LogFactory {

  private final Map<String, MyLogger> loggers = new HashMap<String, MyLogger>();
  private MyLogger defaultLogger;

  public MyLoggerFactory() {
  }

  @Override
  public Logger getLog(String name) {
    MyLogger mylogger = loggers.get(name);
    if (mylogger == null) {
      Logger logger = super.getLog(name);
      if (logger instanceof MyLogger) {
        mylogger = (MyLogger) logger;
      } else {
        mylogger = new MyLogger(logger);
      }
      loggers.put(name, mylogger);
    }

    return mylogger;
  }

  @Override
  public Logger getLog() {
    if (defaultLogger == null) {
      Logger logger = super.getLog();
      if (logger instanceof MyLogger) {
        defaultLogger = (MyLogger) logger;
      } else {
        defaultLogger = new MyLogger(logger);
      }
    }

    return defaultLogger;
  }

}
