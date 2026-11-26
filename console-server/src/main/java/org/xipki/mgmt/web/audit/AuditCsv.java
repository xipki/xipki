// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class AuditCsv {
  private static final List<String> COLUMNS =
      List.of(
          "id",
          "event_time",
          "actor_username",
          "action",
          "result",
          "request_id",
          "resource_type",
          "resource_id",
          "failure_category",
          "details_json",
          "permission_codes");

  public static String encode(List<Map<String, Object>> rows) {
    var output = new StringBuilder(String.join(",", COLUMNS)).append("\r\n");
    for (var row : rows) {
      for (int i = 0; i < COLUMNS.size(); i++) {
        if (i > 0) {
          output.append(',');
        }
        Object value = row.get(COLUMNS.get(i));
        String text = value == null ? "" : value.toString();
        String stripped = text.stripLeading();
        if (!stripped.isEmpty() && "=+-@".indexOf(stripped.charAt(0)) >= 0
            || text.startsWith("\t")
            || text.startsWith("\r")) {
          text = "'" + text;
        }
        output.append('"').append(text.replace("\"", "\"\"")).append('"');
      }
      output.append("\r\n");
      if (output.length() > 2 * 1024 * 1024) {
        throw new ApiException(413, "Export exceeds size limit");
      }
    }
    return output.toString();
  }

  private AuditCsv() {}
}
