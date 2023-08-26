package org.whispersystems.signalservice.internal.serialize;


import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.internal.serialize.protos.AddressProto;

import java.util.Optional;

public final class SignalServiceAddressProtobufSerializer {

  private SignalServiceAddressProtobufSerializer() {
  }

  public static AddressProto toProtobuf(SignalServiceAddress signalServiceAddress) {
    AddressProto.Builder builder = new AddressProto.Builder();

    builder.uuid(signalServiceAddress.getServiceId().toByteString());

    if(signalServiceAddress.getNumber().isPresent()){
      builder.e164(signalServiceAddress.getNumber().get());
    }

    return builder.build();
  }

  public static SignalServiceAddress fromProtobuf(AddressProto addressProto) {
    ServiceId        serviceId = ServiceId.parseOrThrow(addressProto.uuid.toByteArray());
    Optional<String> number    = addressProto.e164 != null ? Optional.of(addressProto.e164) : Optional.empty();

    return new SignalServiceAddress(serviceId, number);
  }
}
