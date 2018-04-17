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

package org.xipki.ocsp.war;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class MyServletContextListener implements ServletContextListener {

  public MyServletContextListener() {
  }

  @Override
  public void contextDestroyed(ServletContextEvent contextEvent) {
      System.out.println("contextDestroyed");
      OcspRuntime.shutdown();
  }

  @Override
  public void contextInitialized(ServletContextEvent contextEvent) {
    System.out.println("contextInitialized");
    OcspRuntime.init();
  }

}
