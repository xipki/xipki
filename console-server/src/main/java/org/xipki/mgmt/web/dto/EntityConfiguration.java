// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * Whole-configuration replacement: never merge a stale secret read back into a write.
 *
 * @author palos
 */
public final class EntityConfiguration {
  private EntityConfiguration() {}

  public static void read(NameTypeConfDto dto, String conf, boolean publicConf) {
    dto.setConf(publicConf ? conf : null);
    dto.setConfHidden(!publicConf);
  }

  public static String replacement(NameTypeConfDto request) {
    if (!request.isReplaceConf()) {
      if (request.getConf() != null) {
        throw new IllegalArgumentException("Explicit replacement required");
      }
      return null;
    }
    requireComplete(request.getConf());
    return request.getConf();
  }

  public static void requireComplete(String conf) {
    if (conf == null
        || conf.isBlank()
        || conf.contains("****")
        || conf.contains("<redacted>")
        || conf.contains("<sensitive>")) {
      throw new IllegalArgumentException("Complete configuration required");
    }
  }
}
