/**
 * @file hw_transport.cpp
 * @brief Hardware Wallet Transport Layer Implementation
 *
 * Implements the transport layer for hardware wallet communication,
 * including HID message framing, timeout handling, and device discovery.
 */

#include "hd_wallet/hw/hw_transport.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Error String Conversion
// =============================================================================

const char* transportErrorToString(TransportError error) {
  switch (error) {
    case TransportError::OK:
      return "Success";
    case TransportError::NOT_CONNECTED:
      return "Device not connected";
    case TransportError::DISCONNECTED:
      return "Device disconnected during operation";
    case TransportError::TIMEOUT:
      return "Operation timed out";
    case TransportError::WRITE_FAILED:
      return "Write operation failed";
    case TransportError::READ_FAILED:
      return "Read operation failed";
    case TransportError::INVALID_RESPONSE:
      return "Invalid response from device";
    case TransportError::MESSAGE_TOO_LARGE:
      return "Message too large";
    case TransportError::NOT_INITIALIZED:
      return "Transport not initialized";
    case TransportError::PROTOCOL_ERROR:
      return "Protocol error";
    case TransportError::DEVICE_BUSY:
      return "Device busy";
    case TransportError::USER_CANCELLED:
      return "User cancelled operation";
    case TransportError::BRIDGE_NOT_AVAILABLE:
      return "WASI bridge not available";
    default:
      return "Unknown transport error";
  }
}

Error transportErrorToError(TransportError error) {
  switch (error) {
    case TransportError::OK:
      return Error::OK;
    case TransportError::NOT_CONNECTED:
    case TransportError::DISCONNECTED:
      return Error::DEVICE_NOT_CONNECTED;
    case TransportError::TIMEOUT:
    case TransportError::DEVICE_BUSY:
      return Error::DEVICE_BUSY;
    case TransportError::WRITE_FAILED:
    case TransportError::READ_FAILED:
    case TransportError::INVALID_RESPONSE:
    case TransportError::PROTOCOL_ERROR:
      return Error::DEVICE_COMM_ERROR;
    case TransportError::USER_CANCELLED:
      return Error::USER_CANCELLED;
    case TransportError::BRIDGE_NOT_AVAILABLE:
      return Error::BRIDGE_NOT_SET;
    default:
      return Error::INTERNAL;
  }
}

// =============================================================================
// Device Type Conversion
// =============================================================================

const char* deviceTypeToString(DeviceType type) {
  switch (type) {
    case DeviceType::UNKNOWN:
      return "Unknown";
    case DeviceType::KEEPKEY:
      return "KeepKey";
    case DeviceType::TREZOR_ONE:
      return "Trezor One";
    case DeviceType::TREZOR_T:
      return "Trezor Model T";
    case DeviceType::LEDGER_NANO_S:
      return "Ledger Nano S";
    case DeviceType::LEDGER_NANO_X:
      return "Ledger Nano X";
    case DeviceType::LEDGER_NANO_S_PLUS:
      return "Ledger Nano S Plus";
    default:
      return "Unknown";
  }
}

// =============================================================================
// MessageFrame Implementation
// =============================================================================

size_t MessageFrame::totalSize() const {
  // First packet: channel(2) + tag(1) + seq(2) + length(4) + data
  // Subsequent: channel(2) + tag(1) + seq(2) + data
  constexpr size_t header_first = 9;  // 2 + 1 + 2 + 4
  constexpr size_t header_cont = 5;   // 2 + 1 + 2
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  if (data.size() <= payload_first) {
    return HID_REPORT_SIZE;
  }

  size_t remaining = data.size() - payload_first;
  size_t cont_packets = (remaining + payload_cont - 1) / payload_cont;
  return HID_REPORT_SIZE * (1 + cont_packets);
}

size_t MessageFrame::packetCount() const {
  constexpr size_t header_first = 9;
  constexpr size_t header_cont = 5;
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  if (data.size() <= payload_first) {
    return 1;
  }

  size_t remaining = data.size() - payload_first;
  return 1 + (remaining + payload_cont - 1) / payload_cont;
}

// =============================================================================
// HidTransport Implementation
// =============================================================================

HidTransport::HidTransport(const TransportConfig& config)
  : config_(config), handle_(0) {}

HidTransport::~HidTransport() {
  close();
}

HidTransport::HidTransport(HidTransport&& other) noexcept
  : config_(std::move(other.config_)),
    handle_(other.handle_),
    device_path_(std::move(other.device_path_)) {
  other.handle_ = 0;
}

HidTransport& HidTransport::operator=(HidTransport&& other) noexcept {
  if (this != &other) {
    close();
    config_ = std::move(other.config_);
    handle_ = other.handle_;
    device_path_ = std::move(other.device_path_);
    other.handle_ = 0;
  }
  return *this;
}

TransportError HidTransport::open(const std::string& path) {
  auto& bridge = WasiBridge::instance();

  // Check if bridge is available
  if (!bridge.hasFeature(WasiFeature::USB_HID)) {
    return TransportError::BRIDGE_NOT_AVAILABLE;
  }

  // Close existing connection if any
  if (handle_ > 0) {
    close();
  }

  // Open device
  handle_ = bridge.hidOpen(path);
  if (handle_ <= 0) {
    return TransportError::NOT_CONNECTED;
  }

  device_path_ = path;
  return TransportError::OK;
}

void HidTransport::close() {
  if (handle_ > 0) {
    auto& bridge = WasiBridge::instance();
    bridge.hidClose(handle_);
    handle_ = 0;
    device_path_.clear();
  }
}

TransportError HidTransport::writeRaw(const ByteVector& data) {
  if (handle_ <= 0) {
    return TransportError::NOT_CONNECTED;
  }

  auto& bridge = WasiBridge::instance();

  // Pad to HID report size
  ByteVector padded = data;
  if (padded.size() < HID_REPORT_SIZE) {
    padded.resize(HID_REPORT_SIZE, 0);
  }

  // Attempt write with retries
  for (int attempt = 0; attempt <= config_.max_retries; ++attempt) {
    int32_t written = bridge.hidWrite(handle_, padded);

    if (written > 0) {
      return TransportError::OK;
    }

    if (written == 0) {
      // Device disconnected
      handle_ = 0;
      return TransportError::DISCONNECTED;
    }

    // Retry on transient error
    if (attempt < config_.max_retries) {
      // Note: In real implementation, would use bridge time callback
      // For now, just retry immediately
      continue;
    }
  }

  return TransportError::WRITE_FAILED;
}

TransportError HidTransport::readRaw(ByteVector& buffer, uint32_t timeout_ms) {
  if (handle_ <= 0) {
    return TransportError::NOT_CONNECTED;
  }

  auto& bridge = WasiBridge::instance();

  if (timeout_ms == 0) {
    timeout_ms = config_.timeout_ms;
  }

  buffer.resize(HID_REPORT_SIZE);

  // Attempt read with retries
  for (int attempt = 0; attempt <= config_.max_retries; ++attempt) {
    int32_t bytes_read = bridge.hidRead(handle_, buffer.data(), buffer.size(), timeout_ms);

    if (bytes_read > 0) {
      buffer.resize(static_cast<size_t>(bytes_read));
      return TransportError::OK;
    }

    if (bytes_read == 0) {
      // Timeout
      return TransportError::TIMEOUT;
    }

    if (bytes_read == -1) {
      // Device disconnected
      handle_ = 0;
      return TransportError::DISCONNECTED;
    }

    // Retry on other errors
    if (attempt < config_.max_retries) {
      continue;
    }
  }

  return TransportError::READ_FAILED;
}

std::vector<ByteVector> HidTransport::frameMessage(
  uint16_t channel_id,
  uint8_t command_tag,
  const ByteVector& data
) {
  std::vector<ByteVector> packets;

  constexpr size_t header_first = 9;  // channel(2) + tag(1) + seq(2) + length(4)
  constexpr size_t header_cont = 5;   // channel(2) + tag(1) + seq(2)
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  size_t offset = 0;
  uint16_t sequence = 0;

  // First packet
  {
    ByteVector packet(HID_REPORT_SIZE, 0);
    size_t pos = 0;

    // Channel ID (big-endian)
    packet[pos++] = static_cast<uint8_t>(channel_id >> 8);
    packet[pos++] = static_cast<uint8_t>(channel_id & 0xFF);

    // Command tag
    packet[pos++] = command_tag;

    // Sequence (big-endian)
    packet[pos++] = static_cast<uint8_t>(sequence >> 8);
    packet[pos++] = static_cast<uint8_t>(sequence & 0xFF);

    // Length (big-endian, 4 bytes)
    uint32_t length = static_cast<uint32_t>(data.size());
    packet[pos++] = static_cast<uint8_t>((length >> 24) & 0xFF);
    packet[pos++] = static_cast<uint8_t>((length >> 16) & 0xFF);
    packet[pos++] = static_cast<uint8_t>((length >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(length & 0xFF);

    // Data
    size_t chunk_size = std::min(payload_first, data.size());
    std::memcpy(packet.data() + pos, data.data(), chunk_size);
    offset += chunk_size;

    packets.push_back(std::move(packet));
    ++sequence;
  }

  // Continuation packets
  while (offset < data.size()) {
    ByteVector packet(HID_REPORT_SIZE, 0);
    size_t pos = 0;

    // Channel ID
    packet[pos++] = static_cast<uint8_t>(channel_id >> 8);
    packet[pos++] = static_cast<uint8_t>(channel_id & 0xFF);

    // Command tag
    packet[pos++] = command_tag;

    // Sequence
    packet[pos++] = static_cast<uint8_t>(sequence >> 8);
    packet[pos++] = static_cast<uint8_t>(sequence & 0xFF);

    // Data
    size_t remaining = data.size() - offset;
    size_t chunk_size = std::min(payload_cont, remaining);
    std::memcpy(packet.data() + pos, data.data() + offset, chunk_size);
    offset += chunk_size;

    packets.push_back(std::move(packet));
    ++sequence;
  }

  return packets;
}

TransportError HidTransport::unframeMessage(
  const std::vector<ByteVector>& packets,
  uint16_t expected_channel,
  uint8_t expected_tag,
  ByteVector& data
) {
  if (packets.empty()) {
    return TransportError::INVALID_RESPONSE;
  }

  constexpr size_t header_first = 9;
  constexpr size_t header_cont = 5;
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  // Parse first packet
  const ByteVector& first = packets[0];
  if (first.size() < header_first) {
    return TransportError::PROTOCOL_ERROR;
  }

  // Verify channel
  uint16_t channel = (static_cast<uint16_t>(first[0]) << 8) | first[1];
  if (channel != expected_channel) {
    return TransportError::PROTOCOL_ERROR;
  }

  // Verify tag
  if (first[2] != expected_tag) {
    return TransportError::PROTOCOL_ERROR;
  }

  // Verify sequence (should be 0)
  uint16_t seq = (static_cast<uint16_t>(first[3]) << 8) | first[4];
  if (seq != 0) {
    return TransportError::PROTOCOL_ERROR;
  }

  // Get length
  uint32_t length = (static_cast<uint32_t>(first[5]) << 24) |
                    (static_cast<uint32_t>(first[6]) << 16) |
                    (static_cast<uint32_t>(first[7]) << 8) |
                    static_cast<uint32_t>(first[8]);

  if (length > MAX_MESSAGE_SIZE) {
    return TransportError::MESSAGE_TOO_LARGE;
  }

  // Extract data
  data.clear();
  data.reserve(length);

  size_t first_chunk = std::min(static_cast<size_t>(payload_first),
                                static_cast<size_t>(length));
  data.insert(data.end(), first.begin() + header_first,
              first.begin() + header_first + first_chunk);

  // Parse continuation packets
  uint16_t expected_seq = 1;
  for (size_t i = 1; i < packets.size() && data.size() < length; ++i) {
    const ByteVector& pkt = packets[i];
    if (pkt.size() < header_cont) {
      return TransportError::PROTOCOL_ERROR;
    }

    // Verify channel
    channel = (static_cast<uint16_t>(pkt[0]) << 8) | pkt[1];
    if (channel != expected_channel) {
      return TransportError::PROTOCOL_ERROR;
    }

    // Verify tag
    if (pkt[2] != expected_tag) {
      return TransportError::PROTOCOL_ERROR;
    }

    // Verify sequence
    seq = (static_cast<uint16_t>(pkt[3]) << 8) | pkt[4];
    if (seq != expected_seq) {
      return TransportError::PROTOCOL_ERROR;
    }
    ++expected_seq;

    // Extract data
    size_t remaining = length - data.size();
    size_t chunk_size = std::min(payload_cont, remaining);
    data.insert(data.end(), pkt.begin() + header_cont,
                pkt.begin() + header_cont + chunk_size);
  }

  if (data.size() != length) {
    return TransportError::INVALID_RESPONSE;
  }

  return TransportError::OK;
}

TransportError HidTransport::sendMessage(
  uint16_t channel_id,
  uint8_t command_tag,
  const ByteVector& data
) {
  if (data.size() > MAX_MESSAGE_SIZE) {
    return TransportError::MESSAGE_TOO_LARGE;
  }

  auto packets = frameMessage(channel_id, command_tag, data);

  for (const auto& packet : packets) {
    TransportError err = writeRaw(packet);
    if (err != TransportError::OK) {
      return err;
    }
  }

  return TransportError::OK;
}

TransportError HidTransport::receiveMessage(
  uint16_t channel_id,
  uint8_t command_tag,
  ByteVector& data,
  uint32_t timeout_ms
) {
  if (timeout_ms == 0) {
    timeout_ms = config_.timeout_ms;
  }

  std::vector<ByteVector> packets;
  uint32_t expected_length = 0;
  size_t received_data = 0;

  constexpr size_t header_first = 9;
  constexpr size_t header_cont = 5;
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  // Read first packet
  {
    ByteVector packet;
    TransportError err = readRaw(packet, timeout_ms);
    if (err != TransportError::OK) {
      return err;
    }

    if (packet.size() < header_first) {
      return TransportError::PROTOCOL_ERROR;
    }

    // Verify channel
    uint16_t channel = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    if (channel != channel_id) {
      return TransportError::PROTOCOL_ERROR;
    }

    // Get length
    expected_length = (static_cast<uint32_t>(packet[5]) << 24) |
                      (static_cast<uint32_t>(packet[6]) << 16) |
                      (static_cast<uint32_t>(packet[7]) << 8) |
                      static_cast<uint32_t>(packet[8]);

    if (expected_length > MAX_MESSAGE_SIZE) {
      return TransportError::MESSAGE_TOO_LARGE;
    }

    received_data = std::min(payload_first, static_cast<size_t>(expected_length));
    packets.push_back(std::move(packet));
  }

  // Read continuation packets
  while (received_data < expected_length) {
    ByteVector packet;
    TransportError err = readRaw(packet, timeout_ms);
    if (err != TransportError::OK) {
      return err;
    }

    size_t remaining = expected_length - received_data;
    received_data += std::min(payload_cont, remaining);
    packets.push_back(std::move(packet));
  }

  return unframeMessage(packets, channel_id, command_tag, data);
}

TransportError HidTransport::exchange(
  uint16_t channel_id,
  uint8_t command_tag,
  const ByteVector& request,
  ByteVector& response,
  uint32_t timeout_ms
) {
  TransportError err = sendMessage(channel_id, command_tag, request);
  if (err != TransportError::OK) {
    return err;
  }

  return receiveMessage(channel_id, command_tag, response, timeout_ms);
}

// =============================================================================
// Transport Factory
// =============================================================================

std::unique_ptr<HidTransport> createTransport(const TransportConfig& config) {
  return std::make_unique<HidTransport>(config);
}

// =============================================================================
// Device Discovery
// =============================================================================

DeviceType identifyDevice(uint16_t vendor_id, uint16_t product_id) {
  // KeepKey
  if (vendor_id == DeviceIds::KEEPKEY_VID &&
      product_id == DeviceIds::KEEPKEY_PID) {
    return DeviceType::KEEPKEY;
  }

  // Trezor (original VID)
  if (vendor_id == DeviceIds::TREZOR_VID) {
    if (product_id == DeviceIds::TREZOR_ONE_PID) {
      return DeviceType::TREZOR_ONE;
    }
    if (product_id == DeviceIds::TREZOR_T_PID) {
      return DeviceType::TREZOR_T;
    }
  }

  // Trezor (SatoshiLabs VID)
  if (vendor_id == DeviceIds::SATOSHILABS_VID) {
    if (product_id == DeviceIds::TREZOR_ONE_PID_ALT) {
      return DeviceType::TREZOR_ONE;
    }
    if (product_id == DeviceIds::TREZOR_T_PID_ALT) {
      return DeviceType::TREZOR_T;
    }
  }

  // Ledger
  if (vendor_id == DeviceIds::LEDGER_VID) {
    if (product_id == DeviceIds::LEDGER_NANO_S_PID) {
      return DeviceType::LEDGER_NANO_S;
    }
    if (product_id == DeviceIds::LEDGER_NANO_X_PID) {
      return DeviceType::LEDGER_NANO_X;
    }
    if (product_id == DeviceIds::LEDGER_NANO_S_PLUS_PID) {
      return DeviceType::LEDGER_NANO_S_PLUS;
    }
  }

  return DeviceType::UNKNOWN;
}

std::vector<HardwareWalletDevice> enumerateDevices() {
  std::vector<HardwareWalletDevice> devices;

  auto& bridge = WasiBridge::instance();

  // Check if HID is available
  if (!bridge.hasFeature(WasiFeature::USB_HID)) {
    return devices;
  }

  // Enumerate HID devices
  auto hid_devices = bridge.hidEnumerate();

  for (const auto& hid : hid_devices) {
    DeviceType type = identifyDevice(hid.vendor_id, hid.product_id);

    if (type != DeviceType::UNKNOWN) {
      HardwareWalletDevice device;
      device.type = type;
      device.path = hid.path;
      device.serial_number = hid.serial_number;
      device.manufacturer = hid.manufacturer;
      device.product = hid.product;
      device.vendor_id = hid.vendor_id;
      device.product_id = hid.product_id;
      device.interface_number = hid.interface_number;

      devices.push_back(std::move(device));
    }
  }

  return devices;
}

std::vector<HardwareWalletDevice> enumerateDevices(DeviceType type) {
  auto all_devices = enumerateDevices();

  std::vector<HardwareWalletDevice> filtered;
  for (auto& device : all_devices) {
    if (device.type == type) {
      filtered.push_back(std::move(device));
    }
  }

  return filtered;
}

} // namespace hw
} // namespace hd_wallet
