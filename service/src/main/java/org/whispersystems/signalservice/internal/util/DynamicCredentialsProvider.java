package org.whispersystems.signalservice.internal.util;

import org.whispersystems.signalservice.api.push.ACI;
import org.whispersystems.signalservice.api.util.CredentialsProvider;

import java.util.UUID;

public class DynamicCredentialsProvider implements CredentialsProvider {

  private ACI    aci;
  private String e164;
  private String password;
  private int deviceId;

  public DynamicCredentialsProvider(ACI aci, String e164, String password, int deviceId) {
    super();
    this.aci = aci;
    this.e164 = e164;
    this.password = password;
    this.deviceId = deviceId;
  }

  @Override
  public ACI getAci() {
    return aci;
  }

  public void setAci(ACI aci) {
    this.aci = aci;
  }

  @Override
  public String getE164() {
    return e164;
  }

  public void setE164(String e164) {
    this.e164 = e164;
  }

  @Override
  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public int getDeviceId() {
    return deviceId;
  }

  public void setDeviceId(int deviceId) {
    this.deviceId = deviceId;
  }

}
