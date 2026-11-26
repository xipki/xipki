// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class ApiResponse<T> {

  public boolean success;
  public T data;
  public String error;

  public static <T> ApiResponse<T> ok(T data) {
    ApiResponse<T> resp = new ApiResponse<>();
    resp.success = true;
    resp.data = data;
    return resp;
  }

  public static ApiResponse<Void> ok() {
    ApiResponse<Void> resp = new ApiResponse<>();
    resp.success = true;
    return resp;
  }

  public static <T> ApiResponse<T> error(String message) {
    ApiResponse<T> resp = new ApiResponse<>();
    resp.success = false;
    resp.error = message;
    return resp;
  }

  public boolean isSuccess() {
    return success;
  }

  public void setSuccess(boolean success) {
    this.success = success;
  }

  public T getData() {
    return data;
  }

  public void setData(T data) {
    this.data = data;
  }

  public String getError() {
    return error;
  }

  public void setError(String error) {
    this.error = error;
  }
}
