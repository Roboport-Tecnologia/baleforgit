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

    /// Single text packet, trailing `\n` stripped. Errors on a control packet.
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

    /// Text packets until flush, trailing newlines stripped.
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

    /// Binary data packets until flush, copied into `out`. Errors if the total
    /// exceeds `max_total_bytes` (guards against unbounded heap growth).
    pub fn read_binary_to<W: Write>(
        &mut self,
        out: &mut W,
        max_total_bytes: u64,
    ) -> io::Result<u64> {
        let mut total = 0u64;
        loop {
            match self.read_packet()? {
                Packet::Flush => return Ok(total),
                Packet::Data(bytes) => {
                    let n = bytes.len() as u64;
                    if total.saturating_add(n) > max_total_bytes {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("pkt-line payload exceeded cap of {max_total_bytes} bytes"),
                        ));
                    }
                    out.write_all(&bytes)?;
                    total += n;
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
        // Append \n so payloads round-trip through newline-aware peers (as git-lfs does).
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

    pub fn write_text_list(&mut self, lines: &[&str]) -> io::Result<()> {
        for line in lines {
            self.write_text(line)?;
        }
        self.flush_packet()
    }

    /// Binary blob as data packets; no trailing flush — call [`flush_packet`] when done.
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
