/*
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.signalservice.api.messages;

import okio.ByteString;

import org.signal.libsignal.metadata.ProtocolInvalidKeyException;
import org.signal.libsignal.metadata.ProtocolInvalidMessageException;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.logging.Log;
import org.signal.libsignal.protocol.message.DecryptionErrorMessage;
import org.signal.libsignal.protocol.message.SenderKeyDistributionMessage;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.GroupMasterKey;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation;
import org.whispersystems.signalservice.api.InvalidMessageStructureException;
import org.whispersystems.signalservice.api.messages.calls.AnswerMessage;
import org.whispersystems.signalservice.api.messages.calls.BusyMessage;
import org.whispersystems.signalservice.api.messages.calls.HangupMessage;
import org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage;
import org.whispersystems.signalservice.api.messages.calls.OfferMessage;
import org.whispersystems.signalservice.api.messages.calls.OpaqueMessage;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;
import org.whispersystems.signalservice.api.messages.multidevice.BlockedListMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ConfigurationMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ContactsMessage;
import org.whispersystems.signalservice.api.messages.multidevice.KeysMessage;
import org.whispersystems.signalservice.api.messages.multidevice.MessageRequestResponseMessage;
import org.whispersystems.signalservice.api.messages.multidevice.OutgoingPaymentMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;
import org.whispersystems.signalservice.api.messages.multidevice.RequestMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SentTranscriptMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SignalServiceSyncMessage;
import org.whispersystems.signalservice.api.messages.multidevice.StickerPackOperationMessage;
import org.whispersystems.signalservice.api.messages.multidevice.VerifiedMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ViewOnceOpenMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ViewedMessage;
import org.whispersystems.signalservice.api.messages.shared.SharedContact;
import org.whispersystems.signalservice.api.payments.Money;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.push.ServiceId.PNI;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.storage.StorageKey;
import org.whispersystems.signalservice.api.util.AttachmentPointerUtil;
import org.whispersystems.signalservice.internal.push.AttachmentPointer;
import org.whispersystems.signalservice.internal.push.BodyRange;
import org.whispersystems.signalservice.internal.push.CallMessage;
import org.whispersystems.signalservice.internal.push.Content;
import org.whispersystems.signalservice.internal.push.DataMessage;
import org.whispersystems.signalservice.internal.push.EditMessage;
import org.whispersystems.signalservice.internal.push.GroupContext;
import org.whispersystems.signalservice.internal.push.GroupContextV2;
import org.whispersystems.signalservice.internal.push.Preview;
import org.whispersystems.signalservice.internal.push.ReceiptMessage;
import org.whispersystems.signalservice.internal.push.StoryMessage;
import org.whispersystems.signalservice.internal.push.SyncMessage;
import org.whispersystems.signalservice.internal.push.TextAttachment;
import org.whispersystems.signalservice.internal.push.TypingMessage;
import org.whispersystems.signalservice.internal.push.UnsupportedDataMessageException;
import org.whispersystems.signalservice.internal.push.UnsupportedDataMessageProtocolVersionException;
import org.whispersystems.signalservice.internal.push.Verified;
import org.whispersystems.signalservice.internal.serialize.SignalServiceAddressProtobufSerializer;
import org.whispersystems.signalservice.internal.serialize.SignalServiceMetadataProtobufSerializer;
import org.whispersystems.signalservice.internal.serialize.protos.SignalServiceContentProto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nullable;

import static org.whispersystems.signalservice.internal.push.GroupContext.Type.DELIVER;

@SuppressWarnings("OptionalIsPresent")
public final class SignalServiceContent {

  private static final String TAG = SignalServiceContent.class.getSimpleName();

  private final SignalServiceAddress      sender;
  private final int                       senderDevice;
  private final long                      timestamp;
  private final long                      serverReceivedTimestamp;
  private final long                      serverDeliveredTimestamp;
  private final boolean                   needsReceipt;
  private final SignalServiceContentProto serializedState;
  private final String                    serverUuid;
  private final Optional<byte[]>          groupId;
  private final String                    destinationUuid;

  private final Optional<SignalServiceDataMessage>         message;
  private final Optional<SignalServiceSyncMessage>         synchronizeMessage;
  private final Optional<SignalServiceCallMessage>         callMessage;
  private final Optional<SignalServiceReceiptMessage>      readMessage;
  private final Optional<SignalServiceTypingMessage>       typingMessage;
  private final Optional<SenderKeyDistributionMessage>     senderKeyDistributionMessage;
  private final Optional<DecryptionErrorMessage>           decryptionErrorMessage;
  private final Optional<SignalServiceStoryMessage>        storyMessage;
  private final Optional<SignalServicePniSignatureMessage> pniSignatureMessage;
  private final Optional<SignalServiceEditMessage>         editMessage;

  private SignalServiceContent(SignalServiceDataMessage message,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.ofNullable(message);
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceSyncMessage synchronizeMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.ofNullable(synchronizeMessage);
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceCallMessage callMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.of(callMessage);
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceReceiptMessage receiptMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.of(receiptMessage);
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(DecryptionErrorMessage errorMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.of(errorMessage);
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceTypingMessage typingMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.of(typingMessage);
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SenderKeyDistributionMessage senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = Optional.of(senderKeyDistributionMessage);
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServicePniSignatureMessage pniSignatureMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = Optional.of(pniSignatureMessage);
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceStoryMessage storyMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.of(storyMessage);
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.empty();
  }

  private SignalServiceContent(SignalServiceEditMessage editMessage,
                               Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage,
                               Optional<SignalServicePniSignatureMessage> pniSignatureMessage,
                               SignalServiceAddress sender,
                               int senderDevice,
                               long timestamp,
                               long serverReceivedTimestamp,
                               long serverDeliveredTimestamp,
                               boolean needsReceipt,
                               String serverUuid,
                               Optional<byte[]> groupId,
                               String destinationUuid,
                               SignalServiceContentProto serializedState)
  {
    this.sender                   = sender;
    this.senderDevice             = senderDevice;
    this.timestamp                = timestamp;
    this.serverReceivedTimestamp  = serverReceivedTimestamp;
    this.serverDeliveredTimestamp = serverDeliveredTimestamp;
    this.needsReceipt             = needsReceipt;
    this.serverUuid               = serverUuid;
    this.groupId                  = groupId;
    this.destinationUuid          = destinationUuid;
    this.serializedState          = serializedState;

    this.message                      = Optional.empty();
    this.synchronizeMessage           = Optional.empty();
    this.callMessage                  = Optional.empty();
    this.readMessage                  = Optional.empty();
    this.typingMessage                = Optional.empty();
    this.senderKeyDistributionMessage = senderKeyDistributionMessage;
    this.decryptionErrorMessage       = Optional.empty();
    this.storyMessage                 = Optional.empty();
    this.pniSignatureMessage          = pniSignatureMessage;
    this.editMessage                  = Optional.of(editMessage);
  }

  public Optional<SignalServiceDataMessage> getDataMessage() {
    return message;
  }

  public Optional<SignalServiceSyncMessage> getSyncMessage() {
    return synchronizeMessage;
  }

  public Optional<SignalServiceCallMessage> getCallMessage() {
    return callMessage;
  }

  public Optional<SignalServiceReceiptMessage> getReceiptMessage() {
    return readMessage;
  }

  public Optional<SignalServiceTypingMessage> getTypingMessage() {
    return typingMessage;
  }

  public Optional<SignalServiceStoryMessage> getStoryMessage() {
    return storyMessage;
  }

  public Optional<SenderKeyDistributionMessage> getSenderKeyDistributionMessage() {
    return senderKeyDistributionMessage;
  }

  public Optional<DecryptionErrorMessage> getDecryptionErrorMessage() {
    return decryptionErrorMessage;
  }

  public Optional<SignalServicePniSignatureMessage> getPniSignatureMessage() {
    return pniSignatureMessage;
  }

  public Optional<SignalServiceEditMessage> getEditMessage() {
    return editMessage;
  }

  public SignalServiceAddress getSender() {
    return sender;
  }

  public int getSenderDevice() {
    return senderDevice;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public long getServerReceivedTimestamp() {
    return serverReceivedTimestamp;
  }

  public long getServerDeliveredTimestamp() {
    return serverDeliveredTimestamp;
  }

  public boolean isNeedsReceipt() {
    return needsReceipt;
  }

  public String getServerUuid() {
    return serverUuid;
  }

  public Optional<byte[]> getGroupId() {
    return groupId;
  }

  public String getDestinationServiceId() {
    return destinationUuid;
  }

  public byte[] serialize() {
    return serializedState.encode();
  }

  public static @Nullable SignalServiceContent deserialize(byte[] data) {
    try {
      if (data == null) return null;

      SignalServiceContentProto signalServiceContentProto = SignalServiceContentProto.ADAPTER.decode(data);

      return createFromProto(signalServiceContentProto);
    } catch (IOException | ProtocolInvalidMessageException | ProtocolInvalidKeyException |
             UnsupportedDataMessageException | InvalidMessageStructureException e) {
      // We do not expect any of these exceptions if this byte[] has come from serialize.
      throw new AssertionError(e);
    }
  }

  public static @Nullable SignalServiceContent createFrom(SignalServiceAddress localAddress, SignalServiceMetadata metadata, Content content) throws ProtocolInvalidKeyException, ProtocolInvalidMessageException, UnsupportedDataMessageException, InvalidMessageStructureException {
    final var contentProto = new SignalServiceContentProto.Builder().localAddress(SignalServiceAddressProtobufSerializer.toProtobuf(localAddress))
                                                                    .metadata(SignalServiceMetadataProtobufSerializer.toProtobuf(metadata))
                                                                    .content(content)
                                                                    .build();

    return createFromProto(contentProto);
  }

  /**
   * Takes internal protobuf serialization format and processes it into a {@link SignalServiceContent}.
   */
  public static @Nullable SignalServiceContent createFromProto(SignalServiceContentProto serviceContentProto)
      throws ProtocolInvalidMessageException, ProtocolInvalidKeyException, UnsupportedDataMessageException, InvalidMessageStructureException
  {
    SignalServiceMetadata metadata     = SignalServiceMetadataProtobufSerializer.fromProtobuf(serviceContentProto.metadata);
    SignalServiceAddress  localAddress = SignalServiceAddressProtobufSerializer.fromProtobuf(serviceContentProto.localAddress);

    if (serviceContentProto.legacyDataMessage != null) {
      throw new InvalidMessageStructureException("Legacy message!");
    } else if (serviceContentProto.content != null) {
      Content                                message                      = serviceContentProto.content;
      Optional<SenderKeyDistributionMessage> senderKeyDistributionMessage = Optional.empty();

      if (message.senderKeyDistributionMessage != null) {
        try {
          senderKeyDistributionMessage = Optional.of(new SenderKeyDistributionMessage(message.senderKeyDistributionMessage.toByteArray()));
        } catch (LegacyMessageException | InvalidMessageException | InvalidVersionException |
                 InvalidKeyException e) {
          Log.w(TAG, "Failed to parse SenderKeyDistributionMessage!", e);
        }
      }

      Optional<SignalServicePniSignatureMessage> pniSignatureMessage = Optional.empty();

      if (message.pniSignatureMessage != null && message.pniSignatureMessage.pni != null && message.pniSignatureMessage.signature != null) {
        PNI pni = PNI.parseOrNull(message.pniSignatureMessage.pni.toByteArray());
        if (pni != null) {
          pniSignatureMessage = Optional.of(new SignalServicePniSignatureMessage(pni, message.pniSignatureMessage.signature.toByteArray()));
        } else {
          Log.w(TAG, "Invalid PNI on PNI signature message! Ignoring.");
        }
      }

      if (message.dataMessage != null) {
        return new SignalServiceContent(createSignalServiceDataMessage(metadata, message.dataMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        metadata.isNeedsReceipt(),
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.syncMessage != null && localAddress.matches(metadata.getSender())) {
        return new SignalServiceContent(createSynchronizeMessage(metadata, message.syncMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        metadata.isNeedsReceipt(),
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.callMessage != null) {
        return new SignalServiceContent(createCallMessage(message.callMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        metadata.isNeedsReceipt(),
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.receiptMessage != null) {
        return new SignalServiceContent(createReceiptMessage(metadata, message.receiptMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        metadata.isNeedsReceipt(),
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.typingMessage != null) {
        return new SignalServiceContent(createTypingMessage(metadata, message.typingMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        false,
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.decryptionErrorMessage != null) {
        return new SignalServiceContent(createDecryptionErrorMessage(metadata, message.decryptionErrorMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        metadata.isNeedsReceipt(),
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.storyMessage != null) {
        return new SignalServiceContent(createStoryMessage(message.storyMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        false,
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (pniSignatureMessage.isPresent()) {
        return new SignalServiceContent(pniSignatureMessage.get(),
                                        senderKeyDistributionMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        false,
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (message.editMessage != null) {
        return new SignalServiceContent(createEditMessage(metadata, message.editMessage),
                                        senderKeyDistributionMessage,
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        false,
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      } else if (senderKeyDistributionMessage.isPresent()) {
        // IMPORTANT: This block should always be last, since you can pair SKDM's with other content
        return new SignalServiceContent(senderKeyDistributionMessage.get(),
                                        pniSignatureMessage,
                                        metadata.getSender(),
                                        metadata.getSenderDevice(),
                                        metadata.getTimestamp(),
                                        metadata.getServerReceivedTimestamp(),
                                        metadata.getServerDeliveredTimestamp(),
                                        false,
                                        metadata.getServerGuid(),
                                        metadata.getGroupId(),
                                        metadata.getDestinationUuid(),
                                        serviceContentProto);
      }
    }

    return null;
  }

  private static SignalServiceDataMessage createSignalServiceDataMessage(SignalServiceMetadata metadata,
                                                                         DataMessage content)
      throws UnsupportedDataMessageException, InvalidMessageStructureException
  {
    SignalServiceGroup                  groupInfoV1 = createGroupV1Info(content);
    SignalServiceGroupV2                groupInfoV2 = createGroupV2Info(content);
    Optional<SignalServiceGroupContext> groupContext;

    try {
      groupContext = SignalServiceGroupContext.createOptional(groupInfoV1, groupInfoV2);
    } catch (InvalidMessageException e) {
      throw new InvalidMessageStructureException(e);
    }


    List<SignalServiceAttachment>            attachments      = new LinkedList<>();
    boolean                                  endSession       = content.flags != null && ((content.flags & DataMessage.Flags.END_SESSION.getValue()) != 0);
    boolean                                  expirationUpdate = content.flags != null && ((content.flags & DataMessage.Flags.EXPIRATION_TIMER_UPDATE.getValue()) != 0);
    boolean                                  profileKeyUpdate = content.flags != null && ((content.flags & DataMessage.Flags.PROFILE_KEY_UPDATE.getValue()) != 0);
    boolean                                  isGroupV2        = groupInfoV2 != null;
    SignalServiceDataMessage.Quote           quote            = createQuote(content, isGroupV2);
    List<SharedContact>                      sharedContacts   = createSharedContacts(content);
    List<SignalServicePreview>               previews         = createPreviews(content);
    List<SignalServiceDataMessage.Mention>   mentions         = createMentions(content.bodyRanges, content.body, isGroupV2);
    SignalServiceDataMessage.Sticker         sticker          = createSticker(content);
    SignalServiceDataMessage.Reaction        reaction         = createReaction(content);
    SignalServiceDataMessage.RemoteDelete    remoteDelete     = createRemoteDelete(content);
    SignalServiceDataMessage.GroupCallUpdate groupCallUpdate  = createGroupCallUpdate(content);
    SignalServiceDataMessage.StoryContext    storyContext     = createStoryContext(content);
    SignalServiceDataMessage.GiftBadge       giftBadge        = createGiftBadge(content);
    List<BodyRange>                          bodyRanges       = createBodyRanges(content.bodyRanges, content.body);

    final var requiredProtocolVersion = content.requiredProtocolVersion == null ? 0 : content.requiredProtocolVersion;
    if (requiredProtocolVersion > DataMessage.ProtocolVersion.CURRENT.getValue()) {
      throw new UnsupportedDataMessageProtocolVersionException(DataMessage.ProtocolVersion.CURRENT.getValue(),
                                                               requiredProtocolVersion,
                                                               metadata.getSender().getIdentifier(),
                                                               metadata.getSenderDevice(),
                                                               groupContext);
    }

    SignalServiceDataMessage.Payment payment = createPayment(content);

    if (requiredProtocolVersion > DataMessage.ProtocolVersion.CURRENT.getValue()) {
      throw new UnsupportedDataMessageProtocolVersionException(DataMessage.ProtocolVersion.CURRENT.getValue(),
                                                               requiredProtocolVersion,
                                                               metadata.getSender().getIdentifier(),
                                                               metadata.getSenderDevice(),
                                                               groupContext);
    }

    for (AttachmentPointer pointer : content.attachments) {
      attachments.add(createAttachmentPointer(pointer));
    }

    if (content.timestamp != null && content.timestamp != metadata.getTimestamp()) {
      throw new InvalidMessageStructureException("Timestamps don't match: " + content.timestamp + " vs " + metadata.getTimestamp(),
                                                 metadata.getSender().getIdentifier(),
                                                 metadata.getSenderDevice());
    }

    return SignalServiceDataMessage.newBuilder()
                                   .withTimestamp(metadata.getTimestamp())
                                   .asGroupMessage(groupInfoV1)
                                   .asGroupMessage(groupInfoV2)
                                   .withAttachments(attachments)
                                   .withBody(content.body)
                                   .asEndSessionMessage(endSession)
                                   .withExpiration(content.expireTimer == null ? 0 : content.expireTimer)
                                   .asExpirationUpdate(expirationUpdate)
                                   .withProfileKey(content.profileKey != null ? content.profileKey.toByteArray() : null)
                                   .asProfileKeyUpdate(profileKeyUpdate)
                                   .withQuote(quote)
                                   .withSharedContacts(sharedContacts)
                                   .withPreviews(previews)
                                   .withMentions(mentions)
                                   .withSticker(sticker)
                                   .withViewOnce(Boolean.TRUE.equals(content.isViewOnce))
                                   .withReaction(reaction)
                                   .withRemoteDelete(remoteDelete)
                                   .withGroupCallUpdate(groupCallUpdate)
                                   .withPayment(payment)
                                   .withStoryContext(storyContext)
                                   .withGiftBadge(giftBadge)
                                   .withBodyRanges(bodyRanges)
                                   .build();
  }

  private static SignalServiceSyncMessage createSynchronizeMessage(SignalServiceMetadata metadata,
                                                                   SyncMessage content)
      throws ProtocolInvalidKeyException, UnsupportedDataMessageException, InvalidMessageStructureException
  {
    if (content.sent != null) {
      Map<ServiceId, Boolean>             unidentifiedStatuses = new HashMap<>();
      SyncMessage.Sent                    sentContent          = content.sent;
      Optional<SignalServiceDataMessage>  dataMessage          = sentContent.message != null ? Optional.of(createSignalServiceDataMessage(metadata, sentContent.message)) : Optional.empty();
      Optional<SignalServiceStoryMessage> storyMessage         = sentContent.storyMessage != null ? Optional.of(createStoryMessage(sentContent.storyMessage)) : Optional.empty();
      Optional<SignalServiceEditMessage>  editMessage          = sentContent.editMessage != null ? Optional.of(createEditMessage(metadata, sentContent.editMessage)) : Optional.empty();
      Optional<SignalServiceAddress> address = SignalServiceAddress.isValidAddress(sentContent.destinationServiceId)
                                               ? Optional.of(new SignalServiceAddress(ServiceId.parseOrThrow(sentContent.destinationServiceId), sentContent.destinationE164))
                                               : Optional.empty();
      Set<SignalServiceStoryMessageRecipient> recipientManifest = sentContent.storyMessageRecipients
          .stream()
          .map(SignalServiceContent::createSignalServiceStoryMessageRecipient)
          .collect(Collectors.toSet());

      if (address.isEmpty() &&
          dataMessage.flatMap(SignalServiceDataMessage::getGroupContext).isEmpty() &&
          storyMessage.flatMap(SignalServiceStoryMessage::getGroupContext).isEmpty() &&
          recipientManifest.isEmpty()) {
        throw new InvalidMessageStructureException("SyncMessage missing destination, group ID, and recipient manifest!");
      }

      for (SyncMessage.Sent.UnidentifiedDeliveryStatus status : sentContent.unidentifiedStatus) {
        if (SignalServiceAddress.isValidAddress(status.destinationServiceId, null)) {
          unidentifiedStatuses.put(ServiceId.parseOrNull(status.destinationServiceId), status.unidentified);
        } else {
          Log.w(TAG, "Encountered an invalid UnidentifiedDeliveryStatus in a SentTranscript! Ignoring.");
        }
      }

      return SignalServiceSyncMessage.forSentTranscript(new SentTranscriptMessage(address,
                                                                                  sentContent.timestamp,
                                                                                  dataMessage,
                                                                                  sentContent.expirationStartTimestamp == null ? 0 : sentContent.expirationStartTimestamp,
                                                                                  unidentifiedStatuses,
                                                                                  Boolean.TRUE.equals(sentContent.isRecipientUpdate),
                                                                                  storyMessage,
                                                                                  recipientManifest,
                                                                                  editMessage));
    }

    if (content.request != null) {
      return SignalServiceSyncMessage.forRequest(new RequestMessage(content.request));
    }

    if (content.read.size() > 0) {
      List<ReadMessage> readMessages = new LinkedList<>();

      for (SyncMessage.Read read : content.read) {
        ACI aci = ACI.parseOrNull(read.senderAci);
        if (aci != null && read.timestamp != null) {
          readMessages.add(new ReadMessage(aci, read.timestamp));
        } else {
          Log.w(TAG, "Encountered an invalid ReadMessage! Ignoring.");
        }
      }

      return SignalServiceSyncMessage.forRead(readMessages);
    }

    if (content.viewed.size() > 0) {
      List<ViewedMessage> viewedMessages = new LinkedList<>();

      for (SyncMessage.Viewed viewed : content.viewed) {
        ACI aci = ACI.parseOrNull(viewed.senderAci);
        if (aci != null && viewed.timestamp != null) {
          viewedMessages.add(new ViewedMessage(aci, viewed.timestamp));
        } else {
          Log.w(TAG, "Encountered an invalid ReadMessage! Ignoring.");
        }
      }

      return SignalServiceSyncMessage.forViewed(viewedMessages);
    }

    if (content.viewOnceOpen != null) {
      ACI aci = ACI.parseOrNull(content.viewOnceOpen.senderAci);
      if (aci != null) {
        ViewOnceOpenMessage timerRead = new ViewOnceOpenMessage(aci, content.viewOnceOpen.timestamp);
        return SignalServiceSyncMessage.forViewOnceOpen(timerRead);
      } else {
        throw new InvalidMessageStructureException("ViewOnceOpen message has no sender!");
      }
    }

    if (content.verified != null) {
      if (SignalServiceAddress.isValidAddress(content.verified.destinationAci)) {
        try {
          Verified             verified    = content.verified;
          SignalServiceAddress destination = new SignalServiceAddress(ServiceId.parseOrThrow(verified.destinationAci));
          IdentityKey          identityKey = new IdentityKey(verified.identityKey.toByteArray(), 0);

          VerifiedMessage.VerifiedState verifiedState;

          if (verified.state == Verified.State.DEFAULT) {
            verifiedState = VerifiedMessage.VerifiedState.DEFAULT;
          } else if (verified.state == Verified.State.VERIFIED) {
            verifiedState = VerifiedMessage.VerifiedState.VERIFIED;
          } else if (verified.state == Verified.State.UNVERIFIED) {
            verifiedState = VerifiedMessage.VerifiedState.UNVERIFIED;
          } else {
            throw new InvalidMessageStructureException("Unknown state: " + verified.state.getValue(),
                                                       metadata.getSender().getIdentifier(),
                                                       metadata.getSenderDevice());
          }

          return SignalServiceSyncMessage.forVerified(new VerifiedMessage(destination, identityKey, verifiedState, System.currentTimeMillis()));
        } catch (InvalidKeyException e) {
          throw new ProtocolInvalidKeyException(e, metadata.getSender().getIdentifier(), metadata.getSenderDevice());
        }
      } else {
        throw new InvalidMessageStructureException("Verified message has no sender!");
      }
    }

    if (content.stickerPackOperation.size() > 0) {
      List<StickerPackOperationMessage> operations = new LinkedList<>();

      for (SyncMessage.StickerPackOperation operation : content.stickerPackOperation) {
        byte[]                           packId  = operation.packId != null ? operation.packId.toByteArray() : null;
        byte[]                           packKey = operation.packKey != null ? operation.packKey.toByteArray() : null;
        StickerPackOperationMessage.Type type    = null;

        if (operation.type != null) {
          switch (operation.type) {
            case INSTALL:
              type = StickerPackOperationMessage.Type.INSTALL;
              break;
            case REMOVE:
              type = StickerPackOperationMessage.Type.REMOVE;
              break;
          }
        }
        operations.add(new StickerPackOperationMessage(packId, packKey, type));
      }

      return SignalServiceSyncMessage.forStickerPackOperations(operations);
    }

    if (content.blocked != null) {
      List<String>               numbers   = content.blocked.numbers;
      List<String>               uuids     = content.blocked.acis;
      List<SignalServiceAddress> addresses = new ArrayList<>(numbers.size() + uuids.size());
      List<byte[]>               groupIds  = new ArrayList<>(content.blocked.groupIds.size());

      for (String uuid : uuids) {
        Optional<SignalServiceAddress> address = SignalServiceAddress.fromRaw(uuid, null);
        if (address.isPresent()) {
          addresses.add(address.get());
        }
      }

      for (ByteString groupId : content.blocked.groupIds) {
        groupIds.add(groupId.toByteArray());
      }

      return SignalServiceSyncMessage.forBlocked(new BlockedListMessage(addresses, groupIds));
    }

    if (content.configuration != null) {
      Boolean readReceipts                   = content.configuration.readReceipts;
      Boolean unidentifiedDeliveryIndicators = content.configuration.unidentifiedDeliveryIndicators;
      Boolean typingIndicators               = content.configuration.typingIndicators;
      Boolean linkPreviews                   = content.configuration.linkPreviews;

      return SignalServiceSyncMessage.forConfiguration(new ConfigurationMessage(Optional.ofNullable(readReceipts),
                                                                                Optional.ofNullable(unidentifiedDeliveryIndicators),
                                                                                Optional.ofNullable(typingIndicators),
                                                                                Optional.ofNullable(linkPreviews)));
    }

    if (content.fetchLatest != null && content.fetchLatest.type != null) {
      switch (content.fetchLatest.type) {
        case LOCAL_PROFILE:
          return SignalServiceSyncMessage.forFetchLatest(SignalServiceSyncMessage.FetchType.LOCAL_PROFILE);
        case STORAGE_MANIFEST:
          return SignalServiceSyncMessage.forFetchLatest(SignalServiceSyncMessage.FetchType.STORAGE_MANIFEST);
        case SUBSCRIPTION_STATUS:
          return SignalServiceSyncMessage.forFetchLatest(SignalServiceSyncMessage.FetchType.SUBSCRIPTION_STATUS);
      }
    }

    if (content.messageRequestResponse != null && content.messageRequestResponse.type != null) {
      MessageRequestResponseMessage.Type type;

      switch (content.messageRequestResponse.type) {
        case ACCEPT:
          type = MessageRequestResponseMessage.Type.ACCEPT;
          break;
        case DELETE:
          type = MessageRequestResponseMessage.Type.DELETE;
          break;
        case BLOCK:
          type = MessageRequestResponseMessage.Type.BLOCK;
          break;
        case BLOCK_AND_DELETE:
          type = MessageRequestResponseMessage.Type.BLOCK_AND_DELETE;
          break;
        default:
          type = MessageRequestResponseMessage.Type.UNKNOWN;
          break;
      }

      MessageRequestResponseMessage responseMessage;

      if (content.messageRequestResponse.groupId != null) {
        responseMessage = MessageRequestResponseMessage.forGroup(content.messageRequestResponse.groupId.toByteArray(), type);
      } else {
        ACI aci = ACI.parseOrNull(content.messageRequestResponse.threadAci);
        if (aci != null) {
          responseMessage = MessageRequestResponseMessage.forIndividual(aci, type);
        } else {
          throw new InvalidMessageStructureException("Message request response has an invalid thread identifier!");
        }
      }

      return SignalServiceSyncMessage.forMessageRequestResponse(responseMessage);
    }

    if (content.groups != null) {
      return SignalServiceSyncMessage.forGroups(createAttachmentPointer(content.groups.blob));
    }

    if (content.outgoingPayment != null) {
      SyncMessage.OutgoingPayment outgoingPayment = content.outgoingPayment;
      if (outgoingPayment.mobileCoin != null) {
        SyncMessage.OutgoingPayment.MobileCoin mobileCoin = outgoingPayment.mobileCoin;
        Money.MobileCoin                       amount     = Money.picoMobileCoin(mobileCoin.amountPicoMob);
        Money.MobileCoin                       fee        = Money.picoMobileCoin(mobileCoin.feePicoMob);
        ByteString                             address    = mobileCoin.recipientAddress;
        Optional<ServiceId>                    recipient  = Optional.ofNullable(ServiceId.parseOrNull(outgoingPayment.recipientServiceId));

        return SignalServiceSyncMessage.forOutgoingPayment(new OutgoingPaymentMessage(recipient,
                                                                                      amount,
                                                                                      fee,
                                                                                      mobileCoin.receipt,
                                                                                      mobileCoin.ledgerBlockIndex,
                                                                                      mobileCoin.ledgerBlockTimestamp,
                                                                                      address.toByteArray().length == 0 ? Optional.empty() : Optional.of(address.toByteArray()),
                                                                                      Optional.ofNullable(outgoingPayment.note),
                                                                                      mobileCoin.outputPublicKeys,
                                                                                      mobileCoin.spentKeyImages));
      } else {
        return SignalServiceSyncMessage.empty();
      }
    }

    if (content.keys != null && content.keys.storageService != null) {
      byte[] storageKey = content.keys.storageService.toByteArray();

      return SignalServiceSyncMessage.forKeys(new KeysMessage(Optional.of(new StorageKey(storageKey))));
    }

    if (content.contacts != null) {
      return SignalServiceSyncMessage.forContacts(new ContactsMessage(createAttachmentPointer(content.contacts.blob), Boolean.TRUE.equals(content.contacts.complete)));
    }

    if (content.pniChangeNumber != null) {
      return SignalServiceSyncMessage.forPniChangeNumber(content.pniChangeNumber);
    }

    if (content.callEvent != null) {
      return SignalServiceSyncMessage.forCallEvent(content.callEvent);
    }

    return SignalServiceSyncMessage.empty();
  }

  private static SignalServiceStoryMessageRecipient createSignalServiceStoryMessageRecipient(SyncMessage.Sent.StoryMessageRecipient storyMessageRecipient) {
    return new SignalServiceStoryMessageRecipient(
        new SignalServiceAddress(ServiceId.parseOrThrow(storyMessageRecipient.destinationServiceId)),
        storyMessageRecipient.distributionListIds,
        Boolean.TRUE.equals(storyMessageRecipient.isAllowedToReply)
    );
  }

  private static SignalServiceCallMessage createCallMessage(CallMessage content) {
    boolean isMultiRing         = false;
    Integer destinationDeviceId = content.destinationDeviceId;

    if (content.offer != null) {
      CallMessage.Offer offerContent = content.offer;
      return SignalServiceCallMessage.forOffer(new OfferMessage(offerContent.id, offerContent.sdp, OfferMessage.Type.fromProto(offerContent.type), offerContent.opaque != null ? offerContent.opaque.toByteArray() : null), isMultiRing, destinationDeviceId);
    } else if (content.answer != null) {
      CallMessage.Answer answerContent = content.answer;
      return SignalServiceCallMessage.forAnswer(new AnswerMessage(answerContent.id, answerContent.sdp, answerContent.opaque != null ? answerContent.opaque.toByteArray() : null), isMultiRing, destinationDeviceId);
    } else if (content.iceUpdate.size() > 0) {
      List<IceUpdateMessage> iceUpdates = new LinkedList<>();

      for (CallMessage.IceUpdate iceUpdate : content.iceUpdate) {
        iceUpdates.add(new IceUpdateMessage(iceUpdate.id, iceUpdate.opaque != null ? iceUpdate.opaque.toByteArray() : null, iceUpdate.sdp));
      }

      return SignalServiceCallMessage.forIceUpdates(iceUpdates, isMultiRing, destinationDeviceId);
    } else if (content.legacyHangup != null) {
      CallMessage.Hangup hangup = content.legacyHangup;
      return SignalServiceCallMessage.forHangup(new HangupMessage(hangup.id, HangupMessage.Type.fromProto(hangup.type), hangup.deviceId), isMultiRing, destinationDeviceId);
    } else if (content.hangup != null) {
      CallMessage.Hangup hangup = content.hangup;
      return SignalServiceCallMessage.forHangup(new HangupMessage(hangup.id, HangupMessage.Type.fromProto(hangup.type), hangup.deviceId), isMultiRing, destinationDeviceId);
    } else if (content.busy != null) {
      CallMessage.Busy busy = content.busy;
      return SignalServiceCallMessage.forBusy(new BusyMessage(busy.id), isMultiRing, destinationDeviceId);
    } else if (content.opaque != null) {
      CallMessage.Opaque opaque = content.opaque;
      return SignalServiceCallMessage.forOpaque(new OpaqueMessage(opaque.data_.toByteArray(), null), isMultiRing, destinationDeviceId);
    }

    return SignalServiceCallMessage.empty();
  }

  private static SignalServiceReceiptMessage createReceiptMessage(SignalServiceMetadata metadata, ReceiptMessage content) {
    SignalServiceReceiptMessage.Type type;

    if (content.type == ReceiptMessage.Type.DELIVERY) type = SignalServiceReceiptMessage.Type.DELIVERY;
    else if (content.type == ReceiptMessage.Type.READ) type = SignalServiceReceiptMessage.Type.READ;
    else if (content.type == ReceiptMessage.Type.VIEWED) type = SignalServiceReceiptMessage.Type.VIEWED;
    else type = SignalServiceReceiptMessage.Type.UNKNOWN;

    return new SignalServiceReceiptMessage(type, content.timestamp, metadata.getTimestamp());
  }

  private static DecryptionErrorMessage createDecryptionErrorMessage(SignalServiceMetadata metadata, ByteString content) throws InvalidMessageStructureException {
    try {
      return new DecryptionErrorMessage(content.toByteArray());
    } catch (InvalidMessageException e) {
      throw new InvalidMessageStructureException(e, metadata.getSender().getIdentifier(), metadata.getSenderDevice());
    }
  }

  private static SignalServiceTypingMessage createTypingMessage(SignalServiceMetadata metadata, TypingMessage content) throws InvalidMessageStructureException {
    SignalServiceTypingMessage.Action action;

    if (content.action == TypingMessage.Action.STARTED) action = SignalServiceTypingMessage.Action.STARTED;
    else if (content.action == TypingMessage.Action.STOPPED) action = SignalServiceTypingMessage.Action.STOPPED;
    else action = SignalServiceTypingMessage.Action.UNKNOWN;

    if (content.timestamp != null && content.timestamp != metadata.getTimestamp()) {
      throw new InvalidMessageStructureException("Timestamps don't match: " + content.timestamp + " vs " + metadata.getTimestamp(),
                                                 metadata.getSender().getIdentifier(),
                                                 metadata.getSenderDevice());
    }

    return new SignalServiceTypingMessage(action, content.timestamp,
                                          content.groupId != null ? Optional.of(content.groupId.toByteArray()) :
                                          Optional.empty());
  }

  private static SignalServiceStoryMessage createStoryMessage(StoryMessage content) throws InvalidMessageStructureException {
    byte[] profileKey = content.profileKey != null ? content.profileKey.toByteArray() : null;

    if (content.fileAttachment != null) {
      return SignalServiceStoryMessage.forFileAttachment(profileKey,
                                                         createGroupV2Info(content),
                                                         createAttachmentPointer(content.fileAttachment),
                                                         Boolean.TRUE.equals(content.allowsReplies),
                                                         content.bodyRanges);
    } else {
      return SignalServiceStoryMessage.forTextAttachment(profileKey,
                                                         createGroupV2Info(content),
                                                         createTextAttachment(content.textAttachment),
                                                         Boolean.TRUE.equals(content.allowsReplies),
                                                         content.bodyRanges);
    }
  }

  private static SignalServiceEditMessage createEditMessage(SignalServiceMetadata metadata, EditMessage content) throws InvalidMessageStructureException, UnsupportedDataMessageException {
    if (content.dataMessage != null && content.targetSentTimestamp != null) {
      return new SignalServiceEditMessage(content.targetSentTimestamp, createSignalServiceDataMessage(metadata, content.dataMessage));
    } else {
      throw new InvalidMessageStructureException("Missing data message or timestamp from edit message.");
    }
  }

  private static @Nullable SignalServiceDataMessage.Quote createQuote(DataMessage content, boolean isGroupV2)
      throws InvalidMessageStructureException
  {
    if (content.quote == null) return null;

    List<SignalServiceDataMessage.Quote.QuotedAttachment> attachments = new LinkedList<>();

    for (DataMessage.Quote.QuotedAttachment attachment : content.quote.attachments) {
      attachments.add(new SignalServiceDataMessage.Quote.QuotedAttachment(attachment.contentType,
                                                                          attachment.fileName,
                                                                          attachment.thumbnail != null ? createAttachmentPointer(attachment.thumbnail) : null));
    }

    ACI author = ACI.parseOrNull(content.quote.authorAci);
    if (author != null) {
      return new SignalServiceDataMessage.Quote(content.quote.id,
                                                author,
                                                content.quote.text,
                                                attachments,
                                                createMentions(content.quote.bodyRanges, content.quote.text, isGroupV2),
                                                SignalServiceDataMessage.Quote.Type.fromProto(content.quote.type),
                                                createBodyRanges(content.quote.bodyRanges, content.quote.text));
    } else {
      Log.w(TAG, "Quote was missing an author! Returning null.");
      return null;
    }
  }

  private static @Nullable List<SignalServicePreview> createPreviews(DataMessage content) throws InvalidMessageStructureException {
    if (content.preview.size() <= 0) return null;

    List<SignalServicePreview> results = new LinkedList<>();

    for (Preview preview : content.preview) {
      results.add(createPreview(preview));
    }

    return results;
  }

  private static SignalServicePreview createPreview(Preview preview) throws InvalidMessageStructureException {
    SignalServiceAttachment attachment = null;

    if (preview.image != null) {
      attachment = createAttachmentPointer(preview.image);
    }

    return new SignalServicePreview(preview.url,
                                    preview.title,
                                    preview.description,
                                    preview.date,
                                    Optional.ofNullable(attachment));
  }

  private static @Nullable List<SignalServiceDataMessage.Mention> createMentions(List<BodyRange> bodyRanges, String body, boolean isGroupV2)
      throws InvalidMessageStructureException
  {
    if (bodyRanges == null || bodyRanges.isEmpty() || body == null) {
      return null;
    }

    List<SignalServiceDataMessage.Mention> mentions = new LinkedList<>();

    for (BodyRange bodyRange : bodyRanges) {
      if (bodyRange.mentionAci != null) {
        try {
          mentions.add(new SignalServiceDataMessage.Mention(ServiceId.parseOrThrow(bodyRange.mentionAci), bodyRange.start, bodyRange.length));
        } catch (IllegalArgumentException e) {
          throw new InvalidMessageStructureException("Invalid body range!");
        }
      }
    }

    if (mentions.size() > 0 && !isGroupV2) {
      Log.w(TAG, "Mentions received in non-GV2 message");
    }

    return mentions;
  }

  private static @Nullable List<BodyRange> createBodyRanges(List<BodyRange> bodyRanges, String body) {
    if (bodyRanges == null || bodyRanges.isEmpty() || body == null) {
      return null;
    }

    List<BodyRange> ranges = new LinkedList<>();

    for (BodyRange bodyRange : bodyRanges) {
      if (bodyRange.style != null) {
        ranges.add(bodyRange);
      }
    }

    return ranges;
  }

  private static @Nullable SignalServiceDataMessage.Sticker createSticker(DataMessage content) throws InvalidMessageStructureException {
    if (content.sticker == null ||
        content.sticker.packId == null ||
        content.sticker.packKey == null ||
        content.sticker.stickerId == null ||
        content.sticker.data_ == null) {
      return null;
    }

    DataMessage.Sticker sticker = content.sticker;

    return new SignalServiceDataMessage.Sticker(sticker.packId.toByteArray(),
                                                sticker.packKey.toByteArray(),
                                                sticker.stickerId,
                                                sticker.emoji,
                                                createAttachmentPointer(sticker.data_));
  }

  private static @Nullable SignalServiceDataMessage.Reaction createReaction(DataMessage content) {
    if (content.reaction == null ||
        content.reaction.emoji == null ||
        content.reaction.targetAuthorAci == null ||
        content.reaction.targetSentTimestamp == null) {
      return null;
    }

    DataMessage.Reaction reaction = content.reaction;
    ACI                  aci      = ACI.parseOrNull(reaction.targetAuthorAci);

    if (aci == null) {
      Log.w(TAG, "Cannot parse author UUID on reaction");
      return null;
    }

    return new SignalServiceDataMessage.Reaction(reaction.emoji,
                                                 Boolean.TRUE.equals(reaction.remove),
                                                 aci,
                                                 reaction.targetSentTimestamp);
  }

  private static @Nullable SignalServiceDataMessage.RemoteDelete createRemoteDelete(DataMessage content) {
    if (content.delete == null || content.delete.targetSentTimestamp == null) {
      return null;
    }

    DataMessage.Delete delete = content.delete;

    return new SignalServiceDataMessage.RemoteDelete(delete.targetSentTimestamp);
  }

  private static @Nullable SignalServiceDataMessage.GroupCallUpdate createGroupCallUpdate(DataMessage content) {
    if (content.groupCallUpdate == null) {
      return null;
    }

    DataMessage.GroupCallUpdate groupCallUpdate = content.groupCallUpdate;

    return new SignalServiceDataMessage.GroupCallUpdate(groupCallUpdate.eraId);
  }

  private static @Nullable SignalServiceDataMessage.Payment createPayment(DataMessage content) throws InvalidMessageStructureException {
    if (content.payment == null) {
      return null;
    }

    DataMessage.Payment payment = content.payment;

    if (payment.notification != null) {
      return new SignalServiceDataMessage.Payment(createPaymentNotification(payment), null);
    } else if (payment.activation != null) {
      return new SignalServiceDataMessage.Payment(null, createPaymentActivation(payment));
    } else {
      throw new InvalidMessageStructureException("Unknown payment item");
    }
  }

  private static @Nullable SignalServiceDataMessage.StoryContext createStoryContext(DataMessage content) throws InvalidMessageStructureException {
    if (content.storyContext == null) {
      return null;
    }

    ACI aci = ACI.parseOrNull(content.storyContext.authorAci);

    if (aci == null) {
      throw new InvalidMessageStructureException("Invalid author ACI!");
    }

    return new SignalServiceDataMessage.StoryContext(aci, content.storyContext.sentTimestamp);
  }

  private static @Nullable SignalServiceDataMessage.GiftBadge createGiftBadge(DataMessage content) throws InvalidMessageStructureException {
    if (content.giftBadge == null) {
      return null;
    }

    if (content.giftBadge.receiptCredentialPresentation == null) {
      throw new InvalidMessageStructureException("GiftBadge does not contain a receipt credential presentation!");
    }

    try {
      ReceiptCredentialPresentation receiptCredentialPresentation = new ReceiptCredentialPresentation(content.giftBadge.receiptCredentialPresentation.toByteArray());
      return new SignalServiceDataMessage.GiftBadge(receiptCredentialPresentation);
    } catch (InvalidInputException invalidInputException) {
      throw new InvalidMessageStructureException(invalidInputException);
    }
  }

  private static SignalServiceDataMessage.PaymentNotification createPaymentNotification(DataMessage.Payment content)
      throws InvalidMessageStructureException
  {
    if (content.notification == null ||
        content.notification.mobileCoin == null) {
      throw new InvalidMessageStructureException("Badly-formatted payment notification!");
    }

    DataMessage.Payment.Notification payment = content.notification;

    return new SignalServiceDataMessage.PaymentNotification(payment.mobileCoin.receipt.toByteArray(), payment.note);
  }

  private static SignalServiceDataMessage.PaymentActivation createPaymentActivation(DataMessage.Payment content)
      throws InvalidMessageStructureException
  {
    if (content.activation == null) {
      throw new InvalidMessageStructureException("Badly-formatted payment activation!");
    }

    DataMessage.Payment.Activation payment = content.activation;

    return new SignalServiceDataMessage.PaymentActivation(payment.type);
  }

  public static @Nullable List<SharedContact> createSharedContacts(DataMessage content) throws InvalidMessageStructureException {
    if (content.contact.size() <= 0) return null;

    List<SharedContact> results = new LinkedList<>();

    for (DataMessage.Contact contact : content.contact) {
      SharedContact.Builder builder = SharedContact.newBuilder()
                                                   .setName(SharedContact.Name.newBuilder()
                                                                              .setDisplay(contact.name.displayName)
                                                                              .setFamily(contact.name.familyName)
                                                                              .setGiven(contact.name.givenName)
                                                                              .setMiddle(contact.name.middleName)
                                                                              .setPrefix(contact.name.prefix)
                                                                              .setSuffix(contact.name.suffix)
                                                                              .build());

      if (contact.address.size() > 0) {
        for (DataMessage.Contact.PostalAddress address : contact.address) {
          SharedContact.PostalAddress.Type type = SharedContact.PostalAddress.Type.HOME;

          switch (address.type) {
            case WORK:
              type = SharedContact.PostalAddress.Type.WORK;
              break;
            case HOME:
              type = SharedContact.PostalAddress.Type.HOME;
              break;
            case CUSTOM:
              type = SharedContact.PostalAddress.Type.CUSTOM;
              break;
          }

          builder.withAddress(SharedContact.PostalAddress.newBuilder()
                                                         .setCity(address.city)
                                                         .setCountry(address.country)
                                                         .setLabel(address.label)
                                                         .setNeighborhood(address.neighborhood)
                                                         .setPobox(address.pobox)
                                                         .setPostcode(address.postcode)
                                                         .setRegion(address.region)
                                                         .setStreet(address.street)
                                                         .setType(type)
                                                         .build());
        }
      }

      if (contact.number.size() > 0) {
        for (DataMessage.Contact.Phone phone : contact.number) {
          SharedContact.Phone.Type type = SharedContact.Phone.Type.HOME;

          switch (phone.type) {
            case HOME:
              type = SharedContact.Phone.Type.HOME;
              break;
            case WORK:
              type = SharedContact.Phone.Type.WORK;
              break;
            case MOBILE:
              type = SharedContact.Phone.Type.MOBILE;
              break;
            case CUSTOM:
              type = SharedContact.Phone.Type.CUSTOM;
              break;
          }

          builder.withPhone(SharedContact.Phone.newBuilder()
                                               .setLabel(phone.label)
                                               .setType(type)
                                               .setValue(phone.value_)
                                               .build());
        }
      }

      if (contact.email.size() > 0) {
        for (DataMessage.Contact.Email email : contact.email) {
          SharedContact.Email.Type type = SharedContact.Email.Type.HOME;

          switch (email.type) {
            case HOME:
              type = SharedContact.Email.Type.HOME;
              break;
            case WORK:
              type = SharedContact.Email.Type.WORK;
              break;
            case MOBILE:
              type = SharedContact.Email.Type.MOBILE;
              break;
            case CUSTOM:
              type = SharedContact.Email.Type.CUSTOM;
              break;
          }

          builder.withEmail(SharedContact.Email.newBuilder()
                                               .setLabel(email.label)
                                               .setType(type)
                                               .setValue(email.value_)
                                               .build());
        }
      }

      if (contact.avatar != null) {
        builder.setAvatar(SharedContact.Avatar.newBuilder()
                                              .withAttachment(createAttachmentPointer(contact.avatar.avatar))
                                              .withProfileFlag(Boolean.TRUE.equals(contact.avatar.isProfile))
                                              .build());
      }

      if (contact.organization != null) {
        builder.withOrganization(contact.organization);
      }

      results.add(builder.build());
    }

    return results;
  }

  private static SignalServiceAttachmentPointer createAttachmentPointer(AttachmentPointer pointer) throws InvalidMessageStructureException {
    return AttachmentPointerUtil.createSignalAttachmentPointer(pointer);
  }

  private static SignalServiceTextAttachment createTextAttachment(TextAttachment attachment) throws InvalidMessageStructureException {
    SignalServiceTextAttachment.Style style = null;
    if (attachment.textStyle != null) {
      switch (attachment.textStyle) {
        case DEFAULT:
          style = SignalServiceTextAttachment.Style.DEFAULT;
          break;
        case REGULAR:
          style = SignalServiceTextAttachment.Style.REGULAR;
          break;
        case BOLD:
          style = SignalServiceTextAttachment.Style.BOLD;
          break;
        case SERIF:
          style = SignalServiceTextAttachment.Style.SERIF;
          break;
        case SCRIPT:
          style = SignalServiceTextAttachment.Style.SCRIPT;
          break;
        case CONDENSED:
          style = SignalServiceTextAttachment.Style.CONDENSED;
          break;
      }
    }

    Optional<String>               text                = Optional.ofNullable(attachment.text);
    Optional<Integer>              textForegroundColor = Optional.ofNullable(attachment.textForegroundColor);
    Optional<Integer>              textBackgroundColor = Optional.ofNullable(attachment.textBackgroundColor);
    Optional<SignalServicePreview> preview             = Optional.ofNullable(attachment.preview != null ? createPreview(attachment.preview) : null);

    if (attachment.gradient != null) {
      TextAttachment.Gradient attachmentGradient = attachment.gradient;

      Integer       startColor = attachmentGradient.startColor;
      Integer       endColor   = attachmentGradient.endColor;
      Integer       angle      = attachmentGradient.angle;
      List<Integer> colors;
      List<Float>   positions;

      if (attachmentGradient.colors.size() > 0 && attachmentGradient.colors.size() == attachmentGradient.positions.size()) {
        colors    = new ArrayList<>(attachmentGradient.colors);
        positions = new ArrayList<>(attachmentGradient.positions);
      } else if (startColor != null && endColor != null) {
        colors    = Arrays.asList(startColor, endColor);
        positions = Arrays.asList(0f, 1f);
      } else {
        colors    = Collections.emptyList();
        positions = Collections.emptyList();
      }

      SignalServiceTextAttachment.Gradient gradient = new SignalServiceTextAttachment.Gradient(Optional.ofNullable(angle),
                                                                                               colors,
                                                                                               positions);

      return SignalServiceTextAttachment.forGradientBackground(text, Optional.ofNullable(style), textForegroundColor, textBackgroundColor, preview, gradient);
    } else if (attachment.color != null) {
      return SignalServiceTextAttachment.forSolidBackground(text, Optional.ofNullable(style), textForegroundColor, textBackgroundColor, preview, attachment.color);
    }
    throw new InvalidMessageStructureException("Missing gradient or color");
  }

  private static SignalServiceGroup createGroupV1Info(DataMessage content) throws InvalidMessageStructureException {
    if (content.group == null) return null;

    SignalServiceGroup.Type type = SignalServiceGroup.Type.UNKNOWN;

    if (content.group.type != null) {
      switch (content.group.type) {
        case DELIVER:
          type = SignalServiceGroup.Type.DELIVER;
          break;
        case UPDATE:
          type = SignalServiceGroup.Type.UPDATE;
          break;
        case QUIT:
          type = SignalServiceGroup.Type.QUIT;
          break;
        case REQUEST_INFO:
          type = SignalServiceGroup.Type.REQUEST_INFO;
          break;
      }
    }

    if (content.group.type != DELIVER) {
      String                         name    = null;
      List<SignalServiceAddress>     members = null;
      SignalServiceAttachmentPointer avatar  = null;

      if (content.group.name != null) {
        name = content.group.name;
      }

      if (content.group.members.size() > 0) {
        members = new ArrayList<>(content.group.members.size());

        for (GroupContext.Member member : content.group.members) {
          if (member.e164 != null && !member.e164.isEmpty()) {
            members.add(new SignalServiceAddress(ServiceId.ACI.UNKNOWN, member.e164));
          } else {
            throw new InvalidMessageStructureException("GroupContext.Member had no address!");
          }
        }
      } else if (content.group.membersE164.size() > 0) {
        members = new ArrayList<>(content.group.membersE164.size());

        for (String member : content.group.membersE164) {
          members.add(new SignalServiceAddress(ServiceId.ACI.UNKNOWN, member));
        }
      }

      if (content.group.avatar != null) {
        AttachmentPointer pointer = content.group.avatar;

        avatar = new SignalServiceAttachmentPointer(pointer.cdnNumber,
                                                    SignalServiceAttachmentRemoteId.from(pointer),
                                                    pointer.contentType,
                                                    pointer.key.toByteArray(),
                                                    Optional.ofNullable(pointer.size),
                                                    Optional.empty(), 0, 0,
                                                    Optional.ofNullable(pointer.digest != null ? pointer.digest.toByteArray() : null),
                                                    Optional.ofNullable(pointer.incrementalDigest != null ? pointer.incrementalDigest.toByteArray() : null),
                                                    Optional.empty(),
                                                    false,
                                                    false,
                                                    false,
                                                    Optional.empty(),
                                                    Optional.empty(),
                                                    pointer.uploadTimestamp != null ? pointer.uploadTimestamp : 0);
      }

      return new SignalServiceGroup(type, content.group.id.toByteArray(), name, members, avatar);
    }

    return new SignalServiceGroup(content.group.id.toByteArray());
  }

  private static @Nullable SignalServiceGroupV2 createGroupV2Info(StoryMessage storyMessage) throws InvalidMessageStructureException {
    if (storyMessage.group == null) {
      return null;
    }
    return createGroupV2Info(storyMessage.group);
  }

  private static @Nullable SignalServiceGroupV2 createGroupV2Info(DataMessage dataMessage) throws InvalidMessageStructureException {
    if (dataMessage.groupV2 == null) {
      return null;
    }
    return createGroupV2Info(dataMessage.groupV2);
  }

  private static @Nullable SignalServiceGroupV2 createGroupV2Info(GroupContextV2 groupV2) throws InvalidMessageStructureException {
    if (groupV2 == null) {
      return null;
    }

    if (groupV2.masterKey == null) {
      throw new InvalidMessageStructureException("No GV2 master key on message");
    }
    if (groupV2.revision == null) {
      throw new InvalidMessageStructureException("No GV2 revision on message");
    }

    SignalServiceGroupV2.Builder builder;
    try {
      builder = SignalServiceGroupV2.newBuilder(new GroupMasterKey(groupV2.masterKey.toByteArray()))
                                    .withRevision(groupV2.revision);
    } catch (InvalidInputException e) {
      throw new InvalidMessageStructureException("Invalid GV2 input!");
    }

    if (groupV2.groupChange != null && groupV2.groupChange.toByteArray().length > 0) {
      builder.withSignedGroupChange(groupV2.groupChange.toByteArray());
    }

    return builder.build();
  }
}
