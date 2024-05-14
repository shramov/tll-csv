use tll::channel::Message;
use tll::channel::*;

use tll::channel::base::*;
use tll::config::Config;
use tll::decimal128::Decimal128;
use tll::error::{Error, Result};
use tll::mem::MemRead;
use tll::scheme::chrono::*;
use tll::scheme::scheme::*;

use chrono::{DateTime, TimeZone, Timelike, Utc};
use csv_core::Writer;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug)]
struct Entry {
    pub message: DetachedMessage,
    pub file: Option<File>,
}

impl Entry {
    fn new(msg: DetachedMessage) -> Self {
        Self {
            message: msg,
            file: None,
        }
    }
}

#[derive(Debug, Default)]
struct CSVWriter {
    pub basedir: PathBuf,
    pub writer: Writer,
    pub buffer: Vec<u8>,
    pub offset: usize,
}

#[derive(Debug, Default)]
struct CSV {
    base: Base,
    writer: CSVWriter,
    messages: HashMap<i32, Entry>,
}

fn convert_string<Ptr: tll::scheme::mem::OffsetPtrImpl>(data: &[u8]) -> Result<String> {
    let size = Ptr::size(&data);
    if size == 0 {
        return Ok("".to_owned());
    }
    let offset = Ptr::offset(&data);
    if data.mem_size() < offset || data.mem_size() < offset + size {
        return Err(Error::from(format!(
            "String field out of bounds: [{}, +{}] > {}",
            offset,
            size,
            data.mem_size()
        )));
    }
    match std::str::from_utf8(&data.as_mem()[offset..offset + size - 1]) {
        Err(_) => Err(Error::from("Invalid UTF8 string")),
        Ok(s) => Ok(s.into()),
    }
}

fn time_suffix(res: TimeResolution) -> &'static str {
    match res {
        TimeResolution::Ns => "ns",
        TimeResolution::Us => "us",
        TimeResolution::Ms => "ms",
        TimeResolution::Second => "s",
        TimeResolution::Minute => "m",
        TimeResolution::Hour => "h",
        TimeResolution::Day => "d",
    }
}

fn convert_datetime(dt: DateTime<Utc>) -> Result<String> {
    let ns = dt.nanosecond();
    Ok(if ns == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else if ns % 1000000 == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    } else if ns % 1000 == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
    })
}

fn convert_integer<'a, T: Integer>(field: &Field<'a>, data: T) -> Result<String>
where
    i64: TryFrom<T>,
{
    match field.sub_type() {
        SubType::None => Ok(data.to_string()),
        SubType::Fixed(prec) => Ok(format!("{}.E-{}", data, prec)),
        SubType::Duration(res) => Ok(format!("{}{}", data, time_suffix(res))),
        SubType::TimePoint(res) => match res {
            TimeResolution::Ns => convert_datetime(TimePoint::<T, Nano>::new_raw(data).as_datetime()?),
            TimeResolution::Us => convert_datetime(TimePoint::<T, Micro>::new_raw(data).as_datetime()?),
            TimeResolution::Ms => convert_datetime(TimePoint::<T, Milli>::new_raw(data).as_datetime()?),
            TimeResolution::Second => convert_datetime(TimePoint::<T, Ratio1>::new_raw(data).as_datetime()?),
            TimeResolution::Minute => convert_datetime(TimePoint::<T, RatioMinute>::new_raw(data).as_datetime()?),
            TimeResolution::Hour => convert_datetime(TimePoint::<T, RatioHour>::new_raw(data).as_datetime()?),
            TimeResolution::Day => convert_datetime(TimePoint::<T, RatioDay>::new_raw(data).as_datetime()?),
        },
        _ => Ok(data.to_string()),
    }
}

fn convert_double<'a>(field: &Field<'a>, data: f64) -> Result<String> {
    match field.sub_type() {
        SubType::None => Ok(data.to_string()),
        SubType::Duration(res) => Ok(format!("{}{}", data, time_suffix(res))),
        SubType::TimePoint(res) => match res {
            TimeResolution::Ns => convert_datetime(Utc.timestamp_nanos((data * 1.) as i64)),
            TimeResolution::Us => convert_datetime(Utc.timestamp_nanos((data * 1000.) as i64)),
            TimeResolution::Ms => convert_datetime(Utc.timestamp_nanos((data * 1000000.) as i64)),
            TimeResolution::Second => convert_datetime(Utc.timestamp_nanos((data * 1000000000.) as i64)),
            TimeResolution::Minute => convert_datetime(Utc.timestamp_nanos((data * 1000000000. / 60.) as i64)),
            TimeResolution::Hour => convert_datetime(Utc.timestamp_nanos((data * 1000000000. / 3600.) as i64)),
            TimeResolution::Day => convert_datetime(Utc.timestamp_nanos((data * 1000000000. / 86400.) as i64)),
        },
        _ => Ok(data.to_string()),
    }
}

fn convert<'a>(field: Field<'a>, data: &[u8]) -> Result<String> {
    match field.get_type() {
        Type::Int8 => convert_integer(&field, data.mem_get_primitive::<i8>(0)),
        Type::Int16 => convert_integer(&field, data.mem_get_primitive::<i16>(0)),
        Type::Int32 => convert_integer(&field, data.mem_get_primitive::<i32>(0)),
        Type::Int64 => convert_integer(&field, data.mem_get_primitive::<i64>(0)),
        Type::UInt8 => convert_integer(&field, data.mem_get_primitive::<u8>(0)),
        Type::UInt16 => convert_integer(&field, data.mem_get_primitive::<u16>(0)),
        Type::UInt32 => convert_integer(&field, data.mem_get_primitive::<u32>(0)),
        Type::UInt64 => convert_integer(&field, data.mem_get_primitive::<u64>(0)),
        Type::Double => convert_double(&field, data.mem_get_primitive::<f64>(0)),
        Type::Decimal128 => Ok(data.mem_get_primitive::<Decimal128>(0).to_string()),
        Type::Bytes(size) => {
            if field.sub_type_raw() == SubTypeRaw::ByteString {
                match std::str::from_utf8(&data.mem_get_bytestring(0, size)) {
                    Err(_) => Err(Error::from("Invalid UTF8 string")),
                    Ok(s) => Ok(s.into()),
                }
            } else {
                Err(Error::from("Non-string bytes are not supported"))
            }
        }
        Type::Pointer { version, .. } => match version {
            // Pointer is checked on open, it is string
            PointerVersion::Default => convert_string::<tll::scheme::mem::OffsetPtrDefault>(data),
            PointerVersion::LegacyShort => convert_string::<tll::scheme::mem::OffsetPtrLegacyShort>(data),
            PointerVersion::LegacyLong => convert_string::<tll::scheme::mem::OffsetPtrLegacyLong>(data),
        },
        t => Err(Error::from(format!("Unsupported type: {:?}", t))),
    }
}

impl CSVWriter {
    fn create_file(&mut self, entry: &Entry) -> Result<File> {
        let message = entry.message.message();

        let mut path = self.basedir.clone();
        path.push(message.name());
        path.set_extension("csv");
        let mut file = File::create(path)?;

        let mut nout;
        (_, _, nout) = self.writer.field("seq".as_bytes(), &mut self.buffer[self.offset..]);
        self.offset += nout;
        for f in message.fields() {
            (_, nout) = self.writer.delimiter(&mut self.buffer[self.offset..]);
            self.offset += nout;
            (_, _, nout) = self.writer.field(f.name().as_bytes(), &mut self.buffer[self.offset..]);
            self.offset += nout;
        }
        (_, nout) = self.writer.terminator(&mut self.buffer[self.offset..]);
        self.offset += nout;
        let slice = &self.buffer[..self.offset];
        self.offset = 0;
        file.write_all(slice)?;

        Ok(file)
    }

    fn post(&mut self, entry: &mut Entry, msg: &Message) -> Result<()> {
        let message = entry.message.message();
        if msg.size < message.size() {
            return Err(Error::from(format!(
                "Invalid message size: {} < minimum {}",
                msg.size,
                message.size()
            )));
        }
        if entry.file.is_none() {
            entry.file = Some(self.create_file(entry)?);
        }

        let mut nout;
        (_, _, nout) = self
            .writer
            .field(msg.seq().to_string().as_bytes(), &mut self.buffer[self.offset..]);
        self.offset += nout;
        for f in message.fields() {
            (_, nout) = self.writer.delimiter(&mut self.buffer[self.offset..]);
            self.offset += nout;
            let string = convert(f, &msg.data()[f.offset()..])
                .map_err(|e| Error::from(format!("Failed to format field {}: {}", f.name(), e)))?;
            (_, _, nout) = self.writer.field(string.as_bytes(), &mut self.buffer[self.offset..]);
            self.offset += nout;
        }
        (_, nout) = self.writer.terminator(&mut self.buffer[self.offset..]);
        self.offset += nout;
        let slice = &self.buffer[..self.offset];
        self.offset = 0;
        entry.file.as_ref().unwrap().write_all(slice)?;
        Ok(())
    }
}

impl Extension for CSV {
    type Inner = Base;

    fn inner(&self) -> &Self::Inner {
        &self.base
    }
    fn inner_mut(&mut self) -> &mut Self::Inner {
        &mut self.base
    }
}

impl ChannelImpl for CSV {
    fn channel_protocol() -> &'static str {
        "csv"
    }
    fn process_policy() -> ProcessPolicy {
        ProcessPolicy::Never
    }

    fn init(&mut self, url: &Config, master: Option<Channel>, context: &Context) -> Result<()> {
        self.writer.basedir = url
            .get("basedir")
            .map(PathBuf::from)
            .ok_or("Missing mandatory 'basedir' parameter")?;
        self.inner_mut().init(url, master, context)?;
        if self.base().scheme_url.is_none() {
            return Err(Error::from("Channel needs scheme"));
        }
        Ok(())
    }

    fn open(&mut self, url: &Config) -> Result<()> {
        self.logger().info(&format!(
            "Open channel, basedir: {}",
            self.writer.basedir.to_str().unwrap_or("")
        ));
        self.writer.writer = Writer::new();
        self.writer.buffer.resize(64 * 1024, 0);

        self.inner_mut().open(url)?;
        if let Some(scheme) = self.base().scheme_data.as_ref() {
            self.messages = self.build_map(scheme)?;
        } else {
            return Err(Error::from("Scheme is mandatory for CSV channel"));
        }
        Ok(())
    }

    fn post(&mut self, msg: &Message) -> Result<()> {
        if let Some(entry) = self.messages.get_mut(&msg.msgid()) {
            self.writer.post(entry, msg)
        } else {
            Err(Error::from(format!("Message {} not found", msg.msgid())))
        }
    }
}

fn check_field<'a>(field: Field<'a>) -> Result<()> {
    match field.get_type() {
        Type::Int8 => Ok(()),
        Type::Int16 => Ok(()),
        Type::Int32 => Ok(()),
        Type::Int64 => Ok(()),
        Type::UInt8 => Ok(()),
        Type::UInt16 => Ok(()),
        Type::UInt32 => Ok(()),
        Type::UInt64 => Ok(()),
        Type::Double => Ok(()),
        Type::Decimal128 => Ok(()),
        Type::Bytes(_) => {
            if field.sub_type_raw() == SubTypeRaw::ByteString {
                Ok(())
            } else {
                Err(Error::from("Non-string bytes are not supported"))
            }
        }
        Type::Pointer { version: _, data } => {
            if field.sub_type_raw() == SubTypeRaw::ByteString && data.type_raw() == TypeRaw::Int8 {
                Ok(())
            } else {
                Err(Error::from("Offset pointers are not supported"))
            }
        }
        t => Err(Error::from(format!("Unsupported type: {:?}", t))),
    }
}

impl CSV {
    fn build_map(&self, scheme: &Scheme) -> Result<HashMap<i32, Entry>> {
        let s = std::rc::Rc::new(scheme.copy());
        let mut r = HashMap::<i32, Entry>::new();
        for m in s.messages() {
            if m.msgid() != 0 {
                for f in m.fields() {
                    check_field(f)?;
                }
                r.insert(m.msgid(), Entry::new(DetachedMessage::new(s.clone(), &m)));
            }
        }
        Ok(r)
    }
}

tll::declare_channel_impl!(csv_impl, CSV);
tll::declare_channel_module!(csv_impl);
