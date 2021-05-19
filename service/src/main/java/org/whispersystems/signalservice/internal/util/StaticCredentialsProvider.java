/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.signalservice.internal.util;

import org.whispersystems.signalservice.api.push.ACI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.util.CredentialsProvider;

public class StaticCredentialsProvider implements CredentialsProvider {

  private final ACI    aci;
  private final String e164;
  private final String password;
  private final int    deviceId;

  public StaticCredentialsProvider(ACI aci, String e164, String password) {
    this(aci, e164, password, SignalServiceAddress.DEFAULT_DEVICE_ID);
  }

  public StaticCredentialsProvider(ACI aci, String e164, String password, int deviceId) {
    this.aci      = aci;
    this.e164     = e164;
    this.password = password;
    this.deviceId = deviceId;
  }

  @Override
  public ACI getAci() {
    return aci;
  }

  @Override
  public String getE164() {
    return e164;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public int getDeviceId() {
    return deviceId;
  }
}
