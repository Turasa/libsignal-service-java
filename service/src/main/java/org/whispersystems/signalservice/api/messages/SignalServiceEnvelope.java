/*
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.signalservice.api.messages;

import okio.ByteString;

import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.util.Preconditions;
import org.whispersystems.signalservice.api.util.UuidUtil;
import org.whispersystems.signalservice.internal.push.Envelope;
import org.whispersystems.signalservice.internal.serialize.protos.SignalServiceEnvelopeProto;
import org.whispersystems.util.Base64;

import java.io.IOException;
import java.util.Optional;

/**
 * This class represents an encrypted Signal Service envelope.
 * <p>
 * The envelope contains the wrapping information, such as the sender, the
 * message timestamp, the encrypted message type, etc.
 *
 * @author Moxie Marlinspike
 */
public class SignalServiceEnvelope {

  private static final String TAG = SignalServiceEnvelope.class.getSimpleName();

  private final Envelope envelope;
  private final long     serverDeliveredTimestamp;

  /**
   * Construct an envelope from a serialized, Base64 encoded SignalServiceEnvelope, encrypted
   * with a signaling key.
   *
   * @param message The serialized SignalServiceEnvelope, base64 encoded and encrypted.
   */
  public SignalServiceEnvelope(String message, long serverDeliveredTimestamp) throws IOException {
    this(Base64.decode(message), serverDeliveredTimestamp);
  }

  /**
   * Construct an envelope from a serialized SignalServiceEnvelope, encrypted with a signaling key.
   *
   * @param input The serialized and (optionally) encrypted SignalServiceEnvelope.
   */
  public SignalServiceEnvelope(byte[] input, long serverDeliveredTimestamp) throws IOException {
    this(Envelope.ADAPTER.decode(input), serverDeliveredTimestamp);
  }

  public SignalServiceEnvelope(Envelope envelope, long serverDeliveredTimestamp) {
    this.envelope                 = envelope;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
  }

  public SignalServiceEnvelope(int type,
                               Optional<SignalServiceAddress> sender,
                               int senderDevice,
                               long timestamp,
                               byte[] content,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               String uuid,
                               String destinationServiceId,
                               boolean urgent,
                               boolean story,
                               byte[] reportingToken,
                               String updatedPni)
  {
    Envelope.Builder builder = new Envelope.Builder()
        .type(Envelope.Type.fromValue(type))
        .sourceDevice(senderDevice)
        .timestamp(timestamp)
        .serverTimestamp(serverReceivedTimestamp)
        .destinationServiceId(destinationServiceId)
        .urgent(urgent)
        .updatedPni(updatedPni)
        .story(story);

    if (sender.isPresent()) {
      builder.sourceServiceId(sender.get().getServiceId().toString());
    }

    if (uuid != null) {
      builder.serverGuid(uuid);
    }

    if (content != null) {
      builder.content(ByteString.of(content));
    }

    if (reportingToken != null) {
      builder.reportingToken(ByteString.of(reportingToken));
    }

    this.envelope                 = builder.build();
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
  }

  public SignalServiceEnvelope(int type,
                               long timestamp,
                               byte[] content,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               String uuid,
                               String destinationServiceId,
                               boolean urgent,
                               boolean story,
                               byte[] reportingToken,
                               String updatedPni)
  {
    Envelope.Builder builder = new Envelope.Builder()
        .type(Envelope.Type.fromValue(type))
        .timestamp(timestamp)
        .serverTimestamp(serverReceivedTimestamp)
        .destinationServiceId(destinationServiceId)
        .urgent(urgent)
        .updatedPni(updatedPni)
        .story(story);

    if (uuid != null) {
      builder.serverGuid(uuid);
    }

    if (content != null) {
      builder.content(ByteString.of(content));
    }

    if (reportingToken != null) {
      builder.reportingToken(ByteString.of(reportingToken));
    }

    this.envelope                 = builder.build();
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
  }

  public String getServerGuid() {
    return envelope.serverGuid;
  }

  public boolean hasServerGuid() {
    return envelope.serverGuid != null;
  }

  /**
   * @return True if either a source E164 or UUID is present.
   */
  public boolean hasSourceServiceId() {
    return envelope.sourceServiceId != null;
  }

  /**
   * @return The envelope's sender as a UUID.
   */
  public Optional<String> getSourceServiceId() {
    return Optional.ofNullable(envelope.sourceServiceId);
  }

  public boolean hasSourceDevice() {
    return envelope.sourceDevice != null;
  }

  /**
   * @return The envelope's sender device ID.
   */
  public int getSourceDevice() {
    return envelope.sourceDevice;
  }

  /**
   * @return The envelope's sender as a SignalServiceAddress.
   */
  public SignalServiceAddress getSourceAddress() {
    return new SignalServiceAddress(ServiceId.parseOrNull(envelope.sourceServiceId));
  }

  /**
   * @return The envelope content type.
   */
  public int getType() {
    return envelope.type.getValue();
  }

  /**
   * @return The timestamp this envelope was sent.
   */
  public long getTimestamp() {
    return envelope.timestamp;
  }

  /**
   * @return The server timestamp of when the server received the envelope.
   */
  public long getServerReceivedTimestamp() {
    return envelope.serverTimestamp;
  }

  /**
   * @return The server timestamp of when the envelope was delivered to us.
   */
  public long getServerDeliveredTimestamp() {
    return serverDeliveredTimestamp;
  }

  /**
   * @return Whether the envelope contains an encrypted SignalServiceContent
   */
  public boolean hasContent() {
    return envelope.content != null;
  }

  /**
   * @return The envelope's encrypted SignalServiceContent.
   */
  public byte[] getContent() {
    return envelope.content.toByteArray();
  }

  /**
   * @return true if the containing message is a {@link org.signal.libsignal.protocol.message.SignalMessage}
   */
  public boolean isSignalMessage() {
    return envelope.type == Envelope.Type.CIPHERTEXT;
  }

  /**
   * @return true if the containing message is a {@link org.signal.libsignal.protocol.message.PreKeySignalMessage}
   */
  public boolean isPreKeySignalMessage() {
    return envelope.type == Envelope.Type.PREKEY_BUNDLE;
  }

  /**
   * @return true if the containing message is a delivery receipt.
   */
  public boolean isReceipt() {
    return envelope.type == Envelope.Type.RECEIPT;
  }

  public boolean isUnidentifiedSender() {
    return envelope.type == Envelope.Type.UNIDENTIFIED_SENDER;
  }

  public boolean isPlaintextContent() {
    return envelope.type == Envelope.Type.PLAINTEXT_CONTENT;
  }

  public boolean hasDestinationUuid() {
    return UuidUtil.isUuid(envelope.destinationServiceId);
  }

  public String getDestinationServiceId() {
    return envelope.destinationServiceId;
  }

  public boolean isUrgent() {
    return envelope.urgent != null && envelope.urgent;
  }

  public boolean hasUpdatedPni() {
    return UuidUtil.isUuid(envelope.updatedPni);
  }

  public String getUpdatedPni() {
    return envelope.updatedPni;
  }

  public boolean isStory() {
    return envelope.story != null && envelope.story;
  }

  public boolean hasReportingToken() {
    return envelope.reportingToken != null;
  }

  public byte[] getReportingToken() {
    return envelope.reportingToken.toByteArray();
  }

  public Envelope getProto() {
    return envelope;
  }

  private SignalServiceEnvelopeProto.Builder serializeToProto() {
    SignalServiceEnvelopeProto.Builder builder = new SignalServiceEnvelopeProto.Builder()
        .type(getType())
        .deviceId(getSourceDevice())
        .timestamp(getTimestamp())
        .serverReceivedTimestamp(getServerReceivedTimestamp())
        .serverDeliveredTimestamp(getServerDeliveredTimestamp())
        .urgent(isUrgent())
        .story(isStory());

    if (getSourceServiceId().isPresent()) {
      builder.sourceServiceId(getSourceServiceId().get());
    }

    if (hasContent()) {
      builder.content(ByteString.of(getContent()));
    }

    if (hasServerGuid()) {
      builder.serverGuid(getServerGuid());
    }

    if (hasDestinationUuid()) {
      builder.destinationServiceId(getDestinationServiceId());
    }

    if (hasReportingToken()) {
      builder.reportingToken(ByteString.of(getReportingToken()));
    }

    return builder;
  }

  public byte[] serialize() {
    return serializeToProto().build().encode();
  }

  public static SignalServiceEnvelope deserialize(byte[] serialized) {
    SignalServiceEnvelopeProto proto = null;
    try {
      proto = SignalServiceEnvelopeProto.ADAPTER.decode(serialized);
    } catch (IOException e) {
      e.printStackTrace();
    }

    Preconditions.checkNotNull(proto);

    ServiceId sourceServiceId = proto.sourceServiceId != null ? ServiceId.parseOrNull(proto.sourceServiceId) : null;

    return new SignalServiceEnvelope(proto.type,
                                     sourceServiceId != null ? Optional.of(new SignalServiceAddress(sourceServiceId)) : Optional.empty(),
                                     proto.deviceId,
                                     proto.timestamp,
                                     proto.content != null ? proto.content.toByteArray() : null,
                                     proto.serverReceivedTimestamp,
                                     proto.serverDeliveredTimestamp,
                                     proto.serverGuid,
                                     proto.destinationServiceId,
                                     proto.urgent != null && proto.urgent,
                                     proto.story != null && proto.story,
                                     proto.reportingToken != null ? proto.reportingToken.toByteArray() : null,
                                     "");
  }
}
