//! Record-bounded DAV parsing; consumers publish only after complete validation.

use std::io::{BufReader, Read};

use dav_xml::{
    FromXml,
    elements::{Multistatus, Response},
};
use quick_xml::{
    Writer,
    events::{BytesStart, Event},
    name::{Namespace, ResolveResult},
    reader::NsReader,
};

use crate::AccountError;

// Wire markup need not fit the decoded metadata budget. A malformed single
// XML token is still bounded by this total, even before the record check.
const MAX_WIRE: u64 = 16 * 1024 * 1024;
const MAX_RECORD: usize = 64 * 1024;

fn invalid() -> AccountError {
    AccountError::new("invalid or incomplete DAV multistatus")
}

fn emit(
    record: &mut Writer<Vec<u8>>,
    root: &BytesStart<'_>,
    consume: &mut impl FnMut(Response) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    if record.get_ref().len() > MAX_RECORD {
        return Err(AccountError::new("directory XML record exceeds its bound"));
    }
    record
        .write_event(Event::End(root.to_end()))
        .map_err(|_| invalid())?;
    if record.get_ref().len() > MAX_RECORD {
        return Err(AccountError::new("directory XML record exceeds its bound"));
    }
    let parsed = Multistatus::from_xml(record.get_ref().clone()).map_err(|_| invalid())?;
    for response in parsed.response {
        consume(response)?;
    }
    record.get_mut().clear();
    Ok(())
}

pub(super) fn responses(
    input: impl Read,
    mut consume: impl FnMut(Response) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    let mut reader = NsReader::from_reader(BufReader::new(input.take(MAX_WIRE + 1)));
    let mut buffer = Vec::new();
    let mut root = None;
    let mut record = Writer::new(Vec::new());
    let mut depth = 0usize;
    let mut closed = false;
    let mut description = false;
    let mut declaration = false;
    let mut records = 0usize;
    loop {
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|error| {
                if matches!(error, quick_xml::Error::Io(_)) {
                    AccountError::retryable_read("cannot read directory response")
                } else {
                    invalid()
                }
            })?;
        let dav_namespace = namespace == ResolveResult::Bound(Namespace("DAV:"));
        if reader.buffer_position() > MAX_WIRE {
            return Err(AccountError::new("directory XML exceeds its bound"));
        }
        match &event {
            Event::Start(start) if depth == 0 => {
                if root.is_some()
                    || closed
                    || !dav_namespace
                    || start.local_name().as_ref() != "multistatus"
                    || start.len() > MAX_RECORD
                {
                    return Err(invalid());
                }
                root = Some(start.clone().into_owned());
                depth = 1;
            }
            Event::Start(_) | Event::Empty(_) if depth > 0 => {
                if depth == 1 {
                    records += 1;
                    if records > super::MAX_ENTRIES + 2 {
                        return Err(AccountError::new(
                            "directory XML record count exceeds its bound",
                        ));
                    }
                    if let Event::Start(start) | Event::Empty(start) = &event
                        && dav_namespace
                        && start.local_name().as_ref() == "responsedescription"
                    {
                        if description {
                            return Err(invalid());
                        }
                        description = true;
                    }
                    record
                        .write_event(Event::Start(root.as_ref().ok_or_else(invalid)?.borrow()))
                        .map_err(|_| invalid())?;
                }
                record.write_event(event.borrow()).map_err(|_| invalid())?;
                if matches!(event, Event::Start(_)) {
                    depth += 1;
                    if depth > 64 {
                        return Err(AccountError::new("DAV XML nesting exceeds the limit"));
                    }
                } else if depth == 1 {
                    emit(
                        &mut record,
                        root.as_ref().ok_or_else(invalid)?,
                        &mut consume,
                    )?;
                }
            }
            Event::End(_) if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    closed = true;
                } else {
                    record.write_event(event.borrow()).map_err(|_| invalid())?;
                    if depth == 1 {
                        emit(
                            &mut record,
                            root.as_ref().ok_or_else(invalid)?,
                            &mut consume,
                        )?;
                    }
                }
            }
            Event::Text(text) if depth <= 1 => {
                if text
                    .as_ref()
                    .bytes()
                    .any(|byte| !byte.is_ascii_whitespace())
                {
                    return Err(invalid());
                }
            }
            Event::Decl(_) if root.is_none() && !declaration => declaration = true,
            Event::Comment(_) | Event::PI(_) if depth <= 1 => (),
            Event::DocType(_) => return Err(AccountError::new("DAV XML DTD is not allowed")),
            Event::Eof => {
                if !closed || depth != 0 {
                    return Err(invalid());
                }
                return Ok(());
            }
            _ if depth > 1 => record.write_event(event.borrow()).map_err(|_| invalid())?,
            _ => return Err(invalid()),
        }
        if reader.buffer_position() > MAX_WIRE || record.get_ref().len() > MAX_RECORD {
            return Err(AccountError::new("directory XML exceeds its bound"));
        }
        buffer.clear();
    }
}
