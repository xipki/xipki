package org.xipki.ca.gateway;

import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.util.exception.ErrorCode;

/**
 * Exception wraps the error response.
 * @author Lijun Liao
 */
public class SdkErrorResponseException extends Exception {

  private ErrorResponse errorResponse;

  public SdkErrorResponseException(ErrorCode errorCode, String message) {
    this(new ErrorResponse(null, errorCode, message));
  }

  public SdkErrorResponseException(ErrorResponse errorResponse) {
    super(errorResponse.toString());
    this.errorResponse = errorResponse;
  }

  public ErrorResponse getErrorResponse() {
    return errorResponse;
  }

}
