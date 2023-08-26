package org.whispersystems.signalservice.internal.serialize;

import okio.ByteString;

import org.whispersystems.signalservice.api.messages.SignalServiceMetadata;
import org.whispersystems.signalservice.internal.serialize.protos.MetadataProto;

import java.util.Optional;

public final class SignalServiceMetadataProtobufSerializer {

  private SignalServiceMetadataProtobufSerializer() {
  }

  public static MetadataProto toProtobuf(SignalServiceMetadata metadata) {
    MetadataProto.Builder builder = new MetadataProto.Builder()
                                                 .address(SignalServiceAddressProtobufSerializer.toProtobuf(metadata.getSender()))
                                                 .senderDevice(metadata.getSenderDevice())
                                                 .needsReceipt(metadata.isNeedsReceipt())
                                                 .timestamp(metadata.getTimestamp())
                                                 .serverReceivedTimestamp(metadata.getServerReceivedTimestamp())
                                                 .serverDeliveredTimestamp(metadata.getServerDeliveredTimestamp())
                                                 .serverGuid(metadata.getServerGuid())
                                                 .destinationUuid(metadata.getDestinationUuid());

    if (metadata.getGroupId().isPresent()) {
      builder.groupId(ByteString.of(metadata.getGroupId().get()));
    }

    return builder.build();
  }

  public static SignalServiceMetadata fromProtobuf(MetadataProto metadata) {
    return new SignalServiceMetadata(SignalServiceAddressProtobufSerializer.fromProtobuf(metadata.address),
                                     metadata.senderDevice,
                                     metadata.timestamp,
                                     metadata.serverReceivedTimestamp,
                                     metadata.serverDeliveredTimestamp,
                                     metadata.needsReceipt,
                                     metadata.serverGuid,
                                     Optional.ofNullable(metadata.groupId).map(ByteString::toByteArray),
                                     metadata.destinationUuid);
  }
}
