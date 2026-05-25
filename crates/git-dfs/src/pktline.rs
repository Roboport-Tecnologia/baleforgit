//! Git pkt-line framing. See `Documentation/gitprotocol-common.txt`:
//! 4-byte hex length prefix (including header), then payload; `0000` =
//! flush, `0001` = delim, `0002` = response-end. Max packet = 65520, so
//! max payload = 65516.

use std::io::{self, BufRead, BufReader, Read, Write};

pub const MAX_PKT_PAYLOAD: usize = 65516;
const HEADER_LEN: usize = 4;

#[derive(Debug)]
pub enum Packet {
    Flush,
    Delim,
    ResponseEnd,
    Data(Vec<u8>),
}

pub struct PktReader<R: Read> {
    inner: BufReader<R>,
}

impl<R: Read> PktReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner: BufReader::new(inner),
        }
    }

    pub fn read_packet(&mut self) -> io::Result<Packet> {
        let mut header = [0u8; HEADER_LEN];
        self.inner.read_exact(&mut header)?;
        let header_str = std::str::from_utf8(&header)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 pkt-line header"))?;
        let len = u16::from_str_radix(header_str, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad pkt-line header '{header_str}'"),
            )
        })? as usize;
        match len {
            0 => Ok(Packet::Flush),
            1 => Ok(Packet::Delim),
            2 => Ok(Packet::ResponseEnd),
            n if n < HEADER_LEN => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("undersized pkt-line length {n}"),
            )),
            n => {
                let payload_len = n - HEADER_LEN;
                let mut buf = vec![0u8; payload_len];
                self.inner.read_exact(&mut buf)?;
                Ok(Packet::Data(buf))
            }
        }
    }

    /// Read a single text packet. Strips a trailing `\n` if present. Errors
    /// if the next packet is a control packet (flush/delim/response-end).
    pub fn read_text(&mut self) -> io::Result<String> {
        match self.read_packet()? {
            Packet::Data(mut bytes) => {
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected text pkt-line, got {other:?}"),
            )),
        }
    }

    /// Read text packets until a flush packet, returning the list with any
    /// trailing newlines stripped.
    pub fn read_text_list(&mut self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        loop {
            match self.read_packet()? {
                Packet::Flush => return Ok(out),
                Packet::Data(mut bytes) => {
                    if bytes.last() == Some(&b'\n') {
                        bytes.pop();
                    }
                    out.push(
                        String::from_utf8(bytes)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                    );
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected text packet or flush, got {other:?}"),
                    ));
                }
            }
        }
    }

    /// Read binary data packets until a flush packet, copying each payload
    /// into `out`. Returns the total bytes copied.
    pub fn read_binary_to<W: Write>(&mut self, out: &mut W) -> io::Result<u64> {
        let mut total = 0u64;
        loop {
            match self.read_packet()? {
                Packet::Flush => return Ok(total),
                Packet::Data(bytes) => {
                    out.write_all(&bytes)?;
                    total += bytes.len() as u64;
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected data packet or flush, got {other:?}"),
                    ));
                }
            }
        }
    }
}

impl<R: Read> Read for PktReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> BufRead for PktReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

pub struct PktWriter<W: Write> {
    inner: W,
}

impl<W: Write> PktWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    pub fn flush_packet(&mut self) -> io::Result<()> {
        // "0000" has no trailing newline, so a LineWriter-backed stdout would
        // hold it in the buffer indefinitely. Explicit flush every time.
        self.inner.write_all(b"0000")?;
        self.inner.flush()
    }

    pub fn write_text(&mut self, line: &str) -> io::Result<()> {
        // Append \n so payloads round-trip through both newline-aware and
        // not-aware peers (git-lfs does the same).
        let bytes = line.as_bytes();
        if bytes.len() + 1 > MAX_PKT_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pkt-line text exceeds 65516 bytes",
            ));
        }
        let total = bytes.len() + 1 + HEADER_LEN;
        write!(self.inner, "{total:04x}")?;
        self.inner.write_all(bytes)?;
        self.inner.write_all(b"\n")
    }

    /// Write each entry as a text packet, terminated by a flush.
    pub fn write_text_list(&mut self, lines: &[&str]) -> io::Result<()> {
        for line in lines {
            self.write_text(line)?;
        }
        self.flush_packet()
    }

    /// Write a binary blob as one or more data packets capped at `MAX_PKT_PAYLOAD`.
    /// Does NOT emit a trailing flush; call [`flush_packet`] when the stream is done.
    pub fn write_binary(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = data.len().min(MAX_PKT_PAYLOAD);
            let total = n + HEADER_LEN;
            write!(self.inner, "{total:04x}")?;
            self.inner.write_all(&data[..n])?;
            data = &data[n..];
        }
        Ok(())
    }

    pub fn write_all_then_flush(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_binary(data)?;
        self.flush_packet()
    }
}

impl<W: Write> Write for PktWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(MAX_PKT_PAYLOAD);
        let total = n + HEADER_LEN;
        write!(self.inner, "{total:04x}")?;
        self.inner.write_all(&buf[..n])?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_text_list() {
        let mut buf = Vec::new();
        {
            let mut w = PktWriter::new(&mut buf);
            w.write_text_list(&["version=2", "capability=clean"])
                .unwrap();
        }
        let mut r = PktReader::new(&buf[..]);
        let list = r.read_text_list().unwrap();
        assert_eq!(list, vec!["version=2", "capability=clean"]);
    }

    #[test]
    fn flush_decodes() {
        let mut r = PktReader::new(&b"0000"[..]);
        assert!(matches!(r.read_packet().unwrap(), Packet::Flush));
    }

    #[test]
    fn binary_payload_round_trip() {
        let mut buf = Vec::new();
        {
            let mut w = PktWriter::new(&mut buf);
            w.write_all_then_flush(b"hello pkt-line").unwrap();
        }
        let mut r = PktReader::new(&buf[..]);
        let mut sink = Vec::new();
        let n = r.read_binary_to(&mut sink).unwrap();
        assert_eq!(n, 14);
        assert_eq!(sink, b"hello pkt-line");
    }

    #[test]
    fn binary_chunks_at_max_payload() {
        let data = vec![0xABu8; MAX_PKT_PAYLOAD * 2 + 100];
        let mut buf = Vec::new();
        {
            let mut w = PktWriter::new(&mut buf);
            w.write_all_then_flush(&data).unwrap();
        }
        let mut r = PktReader::new(&buf[..]);
        let mut sink = Vec::new();
        r.read_binary_to(&mut sink).unwrap();
        assert_eq!(sink, data);
    }
}
