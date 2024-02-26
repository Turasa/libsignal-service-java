package org.whispersystems.signalservice.api.push.exceptions;

public class CaptchaRejectedException extends NonSuccessfulResponseCodeException {
  public CaptchaRejectedException() {
    super(428);
  }
}
