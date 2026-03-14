// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.shell;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.xipki.util.extra.http.Curl;
import org.xipki.util.extra.http.DefaultCurl;

import java.util.Dictionary;
import java.util.Enumeration;

/**
 * Default curl implementation wrapper.
 *
 * @author Lijun Liao (xipki)
 */
@Component(service = Curl.class, immediate = true, configurationPid = "org.xipki.shell.curl")
public class MyDefaultCurl extends DefaultCurl {

  @Activate
  public void activate(ComponentContext context) {
    boolean useSslConf = false;
    String confFile = "xipki/etc/curl.json";

    Dictionary<String, Object> properties = context.getProperties();
    Enumeration<String> keys = properties.keys();
    while (keys.hasMoreElements()) {
      String key = keys.nextElement();
      Object value = properties.get(key);
      if (!(value instanceof String)) {
        continue;
      }

      String sValue = (String) value;
      if (key.equals("confFile")) {
        confFile = sValue;
      } else if (key.equals("useSslConf")) {
        useSslConf = Boolean.parseBoolean(sValue);
      }
    }

    setUseSslConf(useSslConf);
    setConfFile(confFile);
  }

}
