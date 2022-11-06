// https://jvns.ca/blog/2022/11/06/making-a-dns-query-in-ruby-from-scratch/
// https://datatracker.ietf.org/doc/html/rfc1035

use std::net::UdpSocket;
use std::{env, fmt, io, time};

#[derive(Debug)]
struct DNSHeader {
    num_questions: u16,
    num_answers: u16,
    num_auth: u16,
    num_additional: u16,
}

#[derive(Debug)]
struct DNSRecord {
    name: String,
    query_type: QueryType,
    ttl: u32,
    rdata: String,
}

impl fmt::Display for DNSRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t\t{}\t{}\t{}",
            self.name, self.ttl, self.query_type, self.rdata
        )
    }
}

#[derive(Debug)]
enum QueryType {
    A,
    Ns,
    Cname,
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryType::A => write!(f, "A"),
            QueryType::Ns => write!(f, "NS"),
            QueryType::Cname => write!(f, "CNAME"),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(t: QueryType) -> u16 {
        match t {
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
        }
    }
}

impl TryFrom<u16> for QueryType {
    type Error = io::Error;

    fn try_from(t: u16) -> Result<Self, Self::Error> {
        match t {
            1 => Ok(QueryType::A),
            2 => Ok(QueryType::Ns),
            5 => Ok(QueryType::Cname),
            _ => Err(error(&format!("query type not supported: {}", t))),
        }
    }
}

#[derive(Debug)]
struct DNSQuery {
    domain: String,
    query_type: QueryType,
    query_class: u16,
}

impl DNSQuery {
    fn encode(self, query_id: u16) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&query_id.to_be_bytes()); // Query id
        buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // Flags (RD field is set)
        buf.extend_from_slice(&0x0001_u16.to_be_bytes()); // Number of question records
        buf.extend_from_slice(&0x0000_u16.to_be_bytes()); // Number of answer records
        buf.extend_from_slice(&0x0000_u16.to_be_bytes()); // Number of authority records
        buf.extend_from_slice(&0x0000_u16.to_be_bytes()); // Number of additional records

        // Encode domain name
        for segment in self.domain.split('.') {
            buf.push(segment.len() as u8);
            for c in segment.chars() {
                buf.push(c as u8);
            }
        }
        buf.push(0x0);

        let qt: u16 = self.query_type.into();
        buf.extend_from_slice(&qt.to_be_bytes());
        buf.extend_from_slice(&self.query_class.to_be_bytes());

        buf
    }
}

struct Buffer<'a> {
    pos: usize,
    buf: &'a [u8],
}

impl<'a> Buffer<'a> {
    pub fn new(buf: &[u8]) -> Buffer {
        Buffer { pos: 0, buf }
    }

    pub fn read_u8(&mut self) -> u8 {
        let x = self.buf[self.pos];
        self.pos += 1;
        x
    }

    pub fn read_u16(&mut self) -> u16 {
        let x = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        x
    }

    pub fn read_u32(&mut self) -> u32 {
        let x = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        x
    }

    pub fn read_n(&mut self, n: usize) -> &[u8] {
        let x = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        x
    }

    pub fn set_pos(&mut self, pos: usize) -> usize {
        let old_pos = self.pos;
        self.pos = pos;
        old_pos
    }
}

fn read_dns_header(buf: &mut Buffer) -> DNSHeader {
    let _id = buf.read_u16();
    let _flags = buf.read_u16();
    let num_questions = buf.read_u16();
    let num_answers = buf.read_u16();
    let num_auth = buf.read_u16();
    let num_additional = buf.read_u16();
    DNSHeader {
        num_questions,
        num_answers,
        num_auth,
        num_additional,
    }
}

fn read_dns_query(buf: &mut Buffer) -> io::Result<DNSQuery> {
    let domain = read_domain_name(buf)?;
    let query_type = buf.read_u16();
    let query_type = QueryType::try_from(query_type)?;
    let query_class = buf.read_u16();

    Ok(DNSQuery {
        domain,
        query_type,
        query_class,
    })
}

fn read_dns_record(buf: &mut Buffer) -> io::Result<DNSRecord> {
    let domain = read_domain_name(buf)?;
    let query_type = buf.read_u16();
    let query_type = QueryType::try_from(query_type)?;
    let _query_class = buf.read_u16();
    let ttl = buf.read_u32();
    let rdlength = buf.read_u16();
    let rdata = match query_type {
        QueryType::A => {
            assert_eq!(4, rdlength, "invalid A record data");
            format!(
                "{}.{}.{}.{}",
                buf.read_u8(),
                buf.read_u8(),
                buf.read_u8(),
                buf.read_u8()
            )
        }
        QueryType::Ns | QueryType::Cname => read_domain_name(buf)?,
    };

    Ok(DNSRecord {
        name: domain,
        query_type,
        ttl,
        rdata,
    })
}

fn read_domain_name(buf: &mut Buffer) -> io::Result<String> {
    let mut domain = String::new();

    let mut first = true;
    loop {
        let len = buf.read_u8() as usize;
        if len == 0 {
            break;
        }

        // Compression
        if len & 0b11000000 == 0b11000000 {
            let second_byte = buf.read_u8() as usize;
            let offset = ((len & 0x3f) << 8) + second_byte;
            let old_pos = buf.set_pos(offset);
            domain.push_str(&read_domain_name(buf)?);
            buf.set_pos(old_pos);
            break;
        }

        if !first {
            domain.push('.');
        }
        first = false;

        let segment =
            std::str::from_utf8(buf.read_n(len)).map_err(|_| error("invalid domain name"))?;
        domain.push_str(segment);
    }

    Ok(domain)
}

fn error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message)
}

fn run() -> io::Result<()> {
    // Parse CLI args
    let (domain, server) = {
        let mut domain = None;
        let mut server = None;
        for argument in env::args().skip(1) {
            if domain.is_some() && server.is_some() {
                return Err(error("too many arguments"));
            }
            if let Some(s) = argument.strip_prefix('@') {
                server = Some(s.to_string());
            } else {
                domain = Some(argument);
            }
        }
        (
            domain.ok_or_else(|| error("must specify a domain"))?,
            server.unwrap_or_else(|| "1.1.1.1".to_string()),
        )
    };

    let query = {
        // A 16 bit identifier assigned by the program that generates any kind of query. This
        // identifier is copied the corresponding reply and can be used by the requester to match up
        // replies to outstanding queries.
        let query_id = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .map_err(|_| error("unable to calculate duration"))?
            .as_micros() as u16;

        let dns_query = DNSQuery {
            domain,
            query_type: QueryType::A,
            query_class: 1u16, // Internet
        };
        let query = dns_query.encode(query_id);
        query
    };

    // Network
    let buf = {
        let socket = UdpSocket::bind("0.0.0.0:12345")?;
        socket.connect(format!("{}:53", server))?;
        socket.send(&query)?;
        let mut buf = [0; 1024];
        let _len = socket.recv(&mut buf)?;
        buf
    };

    // Parse the response
    let mut buf = Buffer::new(&buf);

    let header = read_dns_header(&mut buf);

    for _ in 0..header.num_questions {
        let _dns_query = read_dns_query(&mut buf);
    }

    for _ in 0..header.num_answers {
        let dns_record = read_dns_record(&mut buf)?;
        println!("{}", dns_record);
    }

    for _ in 0..header.num_auth {
        let dns_record = read_dns_record(&mut buf)?;
        println!("{}", dns_record);
    }

    for _ in 0..header.num_additional {
        let dns_record = read_dns_record(&mut buf)?;
        println!("{}", dns_record);
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    }
}
