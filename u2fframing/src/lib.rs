// Copyright 2020 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate log;
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use std::io;
use std::io::Cursor;

const HEADER_INIT_LEN: usize = 7;
const HEADER_CONT_LEN: usize = 5;
// U2F specs:
// With this approach, a message with a payload less or equal to (s - 7) may be sent as one packet.
// A larger message is then divided into one or more continuation packets, starting with sequence
// number 0, which then increments by one to a maximum of 127.
// With a packet size of 64 bytes (max for full-speed devices), this means that the maximum message
// payload length is 64 - 7 + 128 * (64 - 5) = 7609 bytes.
pub const MAX_PAYLOAD_LEN: usize = 64 - HEADER_INIT_LEN + 128 * (64 - HEADER_CONT_LEN);
// This is the buffer size needed to fit the largest possible u2f package with headers
pub const MAX_LEN: usize = 129 * 64;

// TODO: CID and CMD are verified in the decode method but should maybe be handled by the
// application?
// TODO: decode returns an owned type (Vec) should probably have an interface for decoding into a
// buffer.
pub trait U2FFraming {
    /// Encode function.
    fn encode(&mut self, message: &[u8], buf: &mut [u8]) -> io::Result<usize>;
    /// Decode function. Will fail in case CID and CMD doesn't match stored values.
    fn decode(&mut self, buf: &[u8]) -> io::Result<Option<Vec<u8>>>;

    /// Set the CMD field in case this struct didn't encode the packet
    fn set_cmd(&mut self, cmd: u8);
}

pub fn parse_header(buf: &[u8]) -> io::Result<(u32, u8, u16)> {
    if buf.len() < HEADER_INIT_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Buffer to short to contain header (7 bytes)",
        ));
    }
    let mut rdr = Cursor::new(buf);
    let cid = rdr.read_u32::<BigEndian>()?;
    let cmd = rdr.read_u8()?;
    let len = rdr.read_u16::<BigEndian>()?;
    Ok((cid, cmd, len))
}

pub fn encode_header_init(cid: u32, cmd: u8, len: u16, mut buf: &mut [u8]) -> io::Result<usize> {
    if buf.len() < HEADER_INIT_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Buffer to short to contain header (7 bytes)",
        ));
    }
    buf.write_u32::<BigEndian>(cid)?;
    buf.write_u8(cmd)?;
    buf.write_u16::<BigEndian>(len)?;
    Ok(7)
}

pub fn encode_header_cont(cid: u32, seq: u8, mut buf: &mut [u8]) -> io::Result<usize> {
    if buf.len() < HEADER_CONT_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Buffer to short to contain header (5 bytes)",
        ));
    }
    buf.write_u32::<BigEndian>(cid)?;
    buf.write_u8(seq)?;
    Ok(5)
}

// TODO: Add randomness to CID
pub fn generate_cid() -> u32 {
    0xff00ff00
}

// U2FWS (U2F WebSocket framing protocol) writes u2fhid header and payload as single package (up to
// 7+7609 bytes)
pub struct U2fWs {
    cid: u32,
    cmd: u8,
}

impl U2fWs {
    pub fn new(cmd: u8) -> Self {
        U2fWs {
            cid: generate_cid(),
            cmd,
        }
    }
    // If you want to decode first you need to set the correct cid...
    // TODO: Is this good?
    pub fn with_cid(cid: u32, cmd: u8) -> Self {
        U2fWs { cid, cmd }
    }
}

impl Default for U2fWs {
    fn default() -> Self {
        Self::new(0)
    }
}

impl U2FFraming for U2fWs {
    fn encode(&mut self, message: &[u8], mut buf: &mut [u8]) -> io::Result<usize> {
        let len = encode_header_init(self.cid, self.cmd, message.len() as u16, buf)?;
        buf = &mut buf[len..];
        if buf.len() < message.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message won't fit in buffer",
            ));
        }
        let buf_slice = &mut buf[..message.len()];
        buf_slice.copy_from_slice(message);
        Ok(len + message.len())
    }
    fn decode(&mut self, buf: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let (cid, cmd, len) = parse_header(buf)?;
        if cid != self.cid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wrong CID",
            ));
        }
        if cmd != self.cmd {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wrong CMD",
            ));
        }
        if buf.len() < HEADER_INIT_LEN + len as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid length",
            ));
        }
        Ok(Some(Vec::from(
            &buf[HEADER_INIT_LEN..HEADER_INIT_LEN + len as usize],
        )))
    }

    fn set_cmd(&mut self, cmd: u8) {
        self.cmd = cmd;
    }
}

// U2fHid writes packets / usb reports. 64 bytes at a time
pub struct U2fHid {
    cid: u32,
    cmd: u8,
}

impl U2fHid {
    pub fn new(cmd: u8) -> Self {
        U2fHid {
            cid: generate_cid(),
            cmd,
        }
    }

    pub fn with_cid(cid: u32, cmd: u8) -> Self {
        U2fHid { cid, cmd }
    }

    fn get_encoded_len(len: u16) -> usize {
        if len < 57 {
            64
        } else {
            let len = len - 57;
            64 + 64 * ((59 + len - 1) / 59) as usize
        }
    }
}

impl Default for U2fHid {
    fn default() -> Self {
        Self::new(0)
    }
}

impl U2FFraming for U2fHid {
    fn encode(&mut self, mut message: &[u8], mut buf: &mut [u8]) -> io::Result<usize> {
        let enc_len = Self::get_encoded_len(message.len() as u16);
        debug!("Will encode {} in {}", message.len(), enc_len);
        if buf.len() < enc_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message won't fit in buffer",
            ));
        }
        let len = encode_header_init(self.cid, self.cmd, message.len() as u16, buf)?;
        buf = &mut buf[len..];

        let len = usize::min(64 - len, message.len());
        let buf_slice = &mut buf[..len];
        buf_slice.copy_from_slice(&message[..len]);

        message = &message[len..];
        buf = &mut buf[len..];

        let mut seq = 0;
        while !message.is_empty() {
            let len = encode_header_cont(self.cid, seq as u8, buf)?;
            buf = &mut buf[len..];

            let len = usize::min(64 - len, message.len());
            let buf_slice = &mut buf[..len];
            buf_slice.copy_from_slice(&message[..len]);
            buf = &mut buf[len..];
            message = &message[len..];

            seq += 1;
            if seq > 127 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "More frames than allowed",
                ));
            }
        }

        Ok(enc_len)
    }

    fn decode(&mut self, mut buf: &[u8]) -> io::Result<Option<Vec<u8>>> {
        debug!("decode: {}", buf.len());
        let (cid, cmd, len) = parse_header(buf)?;
        if cid != self.cid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wrong CID",
            ));
        }
        if cmd != self.cmd {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wrong CMD",
            ));
        }
        if buf.len() < Self::get_encoded_len(len) {
            // Need more bytes.
            println!("{}", Self::get_encoded_len(len));
            debug!("need more bytes");
            return Ok(None);
        }

        let mut res = Vec::with_capacity(len as usize);
        let mut left = len as usize;

        let len = usize::min(57, len as usize);
        res.extend_from_slice(&buf[HEADER_INIT_LEN..HEADER_INIT_LEN + len]);
        buf = &buf[HEADER_INIT_LEN + len..];
        left -= len as usize;

        while left > 0 {
            let len = usize::min(59, left);
            res.extend_from_slice(&buf[HEADER_CONT_LEN..HEADER_CONT_LEN + len]);
            buf = &buf[HEADER_CONT_LEN + len..];
            left -= len;
        }
        Ok(Some(res))
    }

    fn set_cmd(&mut self, cmd: u8) {
        self.cmd = cmd;
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn test_u2fhid_encode_single() {
        let mut codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(b"\x01\x02\x03\x04", &mut data[..]).unwrap();
        assert_eq!(len, 64);
        let mut expect = [0u8; 64];
        &expect[..11].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04");
        assert_eq!(&data[..len], &expect[..]);
    }

    #[test]
    fn test_u2fhid_encode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let mut codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(&payload[..], &mut data[..]).unwrap();
        assert_eq!(len, 128);
        let mut expect = [0u8; 128];
        &expect[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        &expect[7..64].copy_from_slice(&payload[..57]);
        &expect[64..69].copy_from_slice(b"\xEE\xEE\xEE\xEE\x00");
        &expect[69..77].copy_from_slice(&payload[57..]);
        assert_eq!(&data[..len], &expect[..]);
    }

    #[test]
    fn test_u2fhid_decode_single() {
        let mut codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut raw = [0u8; 64];
        &raw[..11].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04");
        let data = codec.decode(&raw[..]).unwrap().unwrap();
        assert_eq!(&data[..], b"\x01\x02\x03\x04");
    }

    #[test]
    fn test_u2fhid_decode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let mut codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut raw = [0u8; 128];
        &raw[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        &raw[7..64].copy_from_slice(&payload[..57]);
        &raw[64..69].copy_from_slice(b"\xEE\xEE\xEE\xEE\x00");
        &raw[69..77].copy_from_slice(&payload[57..]);
        let data = codec.decode(&raw[..]).unwrap().unwrap();
        assert_eq!(&data[..], &payload[..]);
    }

    #[test]
    fn test_u2fws_encode_single() {
        let mut codec = U2fWs::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(b"\x01\x02\x03\x04", &mut data[..]).unwrap();
        assert_eq!(len, 11);
        assert_eq!(
            &data[..len],
            b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04"
        );
    }

    #[test]
    fn test_u2fws_encode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let mut codec = U2fWs::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(&payload[..], &mut data[..]).unwrap();
        assert_eq!(len, 72);
        let mut expect = [0u8; 72];
        &expect[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        &expect[7..72].copy_from_slice(&payload[..]);
        assert_eq!(&data[..len], &expect[..]);
    }

    #[test]
    fn test_u2fws_decode_single() {
        let mut codec = U2fWs::with_cid(0xEEEEEEEE, 0x55);
        let data = codec
            .decode(b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04")
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"\x01\x02\x03\x04");
    }

    #[test]
    fn test_u2fws_decode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let mut codec = U2fWs::with_cid(0xEEEEEEEE, 0x55);
        let mut raw = [0u8; 128];
        &raw[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        &raw[7..72].copy_from_slice(&payload[..]);
        let data = codec.decode(&raw[..]).unwrap().unwrap();
        assert_eq!(&data[..], &payload[..]);
    }
}
