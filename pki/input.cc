// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "input.h"

BSSL_NAMESPACE_BEGIN
namespace der {

std::string Input::AsString() const { return std::string(AsStringView()); }

bool operator==(Input lhs, Input rhs) { return Span(lhs) == Span(rhs); }

bool operator!=(Input lhs, Input rhs) { return !(lhs == rhs); }

ByteReader::ByteReader(Input in) : data_(in) {}

bool ByteReader::ReadByte(uint8_t *byte_p) {
  if (!HasMore()) {
    return false;
  }
  *byte_p = data_[0];
  Advance(1);
  return true;
}

bool ByteReader::ReadBytes(size_t len, Input *out) {
  if (len > data_.size()) {
    return false;
  }
  *out = Input(data_.first(len));
  Advance(len);
  return true;
}

// Returns whether there is any more data to be read.
bool ByteReader::HasMore() { return !data_.empty(); }

void ByteReader::Advance(size_t len) {
  BSSL_CHECK(len <= data_.size());
  data_ = data_.subspan(len);
}

}  // namespace der
BSSL_NAMESPACE_END
