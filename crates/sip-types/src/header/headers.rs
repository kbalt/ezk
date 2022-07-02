use super::{ConstNamed, DecodeValues, DynNamed, ExtendValues, HeaderError};
use crate::header::name::Name;
use crate::parse::Parser;
use crate::print::{AppendCtx, Print, PrintCtx};
use bytesstr::BytesStr;
use std::iter::{once, FromIterator};
use std::mem::take;
use std::{fmt, slice};

/// Headers is simple container for SIP-Message headers.
/// The headers are stored as [BytesStr] under its respective [Name].
///
/// Internally it is a `Vec`-backed multimap to keep insertion order
#[derive(Default)]
pub struct Headers {
    parser: Parser,
    entries: Vec<Entry>,
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Headers")
            .field("entries", &self.entries)
            .finish()
    }
}

impl Headers {
    /// Returns a new empty [Headers]
    #[inline]
    pub fn new() -> Self {
        Headers {
            parser: Parser::default(),
            entries: Vec::new(),
        }
    }

    /// Returns a new empty [Headers] with the specified capacity
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Headers {
            parser: Parser::default(),
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Set the [`Parser`] to be used when parsing types.
    pub fn set_parser(&mut self, parser: Parser) {
        self.parser = parser;
    }

    /// Returns if a header with the given name is inside the map.
    #[inline]
    pub fn contains(&self, name: &Name) -> bool {
        self.entries.iter().any(|entry| &entry.name == name)
    }

    /// Inserts `header` using its [`HeaderNamed`] and [`InsertIntoHeaders`] implementation to the front of the list
    #[inline]
    pub fn insert_named_front<H: DynNamed + ExtendValues>(&mut self, header: &H) {
        self.insert_type_front(header.name(), header)
    }

    /// Inserts `header` using its [`InsertIntoHeaders`] implementation to the front of the list
    #[inline]
    pub fn insert_type_front<H: ExtendValues>(&mut self, name: Name, header: &H) {
        let ctx = PrintCtx::default();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            header.extend_values(ctx, values);
        } else {
            self.entries.insert(
                0,
                Entry {
                    name,
                    values: header.create_values(ctx),
                },
            );
        }
    }

    /// Inserts a header value with the given name to the front of the list
    #[inline]
    pub fn insert_front<N, V>(&mut self, name: N, value: V)
    where
        N: Into<Name>,
        V: Print,
    {
        let ctx = PrintCtx::default();
        let name = name.into();
        let value = value.print_ctx(ctx).to_string();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            values.push(value.into());
        } else {
            self.entries.insert(
                0,
                Entry {
                    name,
                    values: OneOrMore::One(value.into()),
                },
            );
        }
    }

    /// Inserts `header` using its [`DynNamed`] and [`ExtendValues`] implementation to the list
    #[inline]
    pub fn insert_named<H: DynNamed + ExtendValues>(&mut self, header: &H) {
        self.insert_type(header.name(), header)
    }

    /// Inserts `header` using its [`ExtendValues`] implementation to the list
    #[inline]
    pub fn insert_type<H: ExtendValues>(&mut self, name: Name, header: &H) {
        let ctx = PrintCtx::default();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            header.extend_values(ctx, values);
        } else {
            self.entries.push(Entry {
                name,
                values: header.create_values(ctx),
            });
        }
    }

    /// Insert a header value with the given name to end of the list
    #[inline]
    pub fn insert<N, V>(&mut self, name: N, value: V)
    where
        N: Into<Name>,
        V: Print,
    {
        let ctx = PrintCtx::default();
        let name = name.into();
        let value = value.print_ctx(ctx).to_string();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            values.push(value.into());
        } else {
            self.entries.push(Entry {
                name,
                values: OneOrMore::One(value.into()),
            });
        }
    }

    /// Remove all headers with the given name
    #[inline]
    pub fn remove(&mut self, name: &Name) -> Option<Vec<BytesStr>> {
        match remove_where(&mut self.entries, |Entry { name: n, .. }| name == n)?.values {
            OneOrMore::One(v) => Some(vec![v]),
            OneOrMore::More(v) => Some(v),
        }
    }

    /// Returns a parsed header `H` and removes it from the map.
    #[inline]
    pub fn take_named<H: ConstNamed + DecodeValues>(&mut self) -> Option<H> {
        self.try_take_named().and_then(Result::ok)
    }

    /// Returns a parsed header `H` and removes it from the map.
    /// Returns `None` instead of a HeaderError if the header is not present.
    #[inline]
    pub fn try_take_named<H: ConstNamed + DecodeValues>(
        &mut self,
    ) -> Option<Result<H, HeaderError>> {
        remove_where(&mut self.entries, |Entry { name, .. }| *name == H::NAME)
            .map(|Entry { values, .. }| values.decode(H::NAME, self.parser))
    }

    /// Returns a parsed header `H`.
    #[inline]
    pub fn get_named<H: ConstNamed + DecodeValues>(&self) -> Result<H, HeaderError> {
        match self.try_get_named() {
            Some(res) => res,
            None => Err(HeaderError::missing(H::NAME)),
        }
    }

    /// Returns a parsed header `H`. Returns `None` instead of an
    /// HeaderError if the header is not present.
    #[inline]
    pub fn try_get_named<H: ConstNamed + DecodeValues>(&self) -> Option<Result<H, HeaderError>> {
        Some(self.entry(&H::NAME)?.values.decode(H::NAME, self.parser))
    }

    /// Takes a closure which edits a named header type.
    #[inline]
    pub fn edit_named<H, F>(&mut self, edit: F) -> Result<(), HeaderError>
    where
        H: ConstNamed + DecodeValues + ExtendValues,
        F: FnOnce(&mut H),
    {
        self.edit(H::NAME, edit)
    }

    // =======================================================

    /// Returns a parsed header `H` and removes it from the map.
    #[inline]
    pub fn take<H: DecodeValues>(&mut self, name: Name) -> Option<H> {
        self.try_take(name).and_then(Result::ok)
    }

    /// Returns a parsed header `H` and removes it from the map.
    /// Returns `None` instead if a HeaderError if header is not present.
    #[inline]
    pub fn try_take<H: DecodeValues>(&mut self, name: Name) -> Option<Result<H, HeaderError>> {
        remove_where(&mut self.entries, |entry| entry.name == name)
            .map(|Entry { values, .. }| values.decode(name, self.parser))
    }

    /// Returns a parsed header `H`.
    #[inline]
    pub fn get<H: DecodeValues>(&self, name: Name) -> Result<H, HeaderError> {
        match self.try_get(name.clone()) {
            Some(res) => res,
            None => Err(HeaderError::missing(name)),
        }
    }

    /// Returns a parsed header `H`. Returns `None` instead a HeaderError if header is not present.
    #[inline]
    pub fn try_get<H: DecodeValues>(&self, name: Name) -> Option<Result<H, HeaderError>> {
        Some(self.entry(&name)?.values.decode(name, self.parser))
    }

    /// Takes a closure which edits a header.
    #[inline]
    pub fn edit<H, F>(&mut self, name: Name, edit: F) -> Result<(), HeaderError>
    where
        H: DecodeValues + ExtendValues,
        F: FnOnce(&mut H),
    {
        let parser = self.parser;
        let entry = self
            .entry_mut(&name)
            .ok_or_else(|| HeaderError::missing(name.clone()))?;

        let mut header = entry.values.decode(name, parser)?;

        (edit)(&mut header);

        entry.values = H::create_values(&header, Default::default());

        Ok(())
    }

    /// Clones all headers with `name` into another [Headers].
    #[inline]
    pub fn clone_into(&self, dest: &mut Self, name: Name) -> Result<(), HeaderError> {
        let Entry { values, .. } = self
            .entry(&name)
            .ok_or_else(|| HeaderError::missing(name.clone()))?;

        match values {
            OneOrMore::One(val) => {
                dest.insert(name, val.clone());
            }
            OneOrMore::More(values) => {
                for val in values {
                    dest.insert(name.clone(), val.clone());
                }
            }
        }

        Ok(())
    }

    /// Drain all headers into another [Headers].
    pub fn drain_into(&mut self, dst: &mut Self) {
        for Entry { name, values } in self.entries.drain(..) {
            match values {
                OneOrMore::One(value) => dst.insert(name, value),
                OneOrMore::More(values) => values
                    .into_iter()
                    .for_each(|value| dst.insert(name.clone(), value)),
            }
        }
    }

    /// Returns the len of the map if it were printed to a buffer
    pub fn printed_len(&self) -> usize {
        let mut len = 0;

        for (name, value) in self.iter() {
            len += name.as_print_str().len();
            len += value.len();
            len += 4;
        }

        len
    }

    /// Returns an iterator over [Name] and [BytesStr] pairs in the map.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, &BytesStr)> + '_ {
        struct Iter<'s> {
            entries: slice::Iter<'s, Entry>,
            current: Option<(&'s Name, slice::Iter<'s, BytesStr>)>,
        }

        impl<'s> Iterator for Iter<'s> {
            type Item = (&'s Name, &'s BytesStr);

            fn next(&mut self) -> Option<Self::Item> {
                if let Some((name, iter)) = &mut self.current {
                    if let Some(val) = iter.next() {
                        return Some((name, val));
                    } else {
                        self.current = None;
                    }
                }

                let entry = self.entries.next()?;

                match &entry.values {
                    OneOrMore::One(val) => Some((&entry.name, val)),
                    OneOrMore::More(values) => {
                        let mut iter = values.iter();
                        let ret = iter.next().expect("empty vec in values");

                        self.current = Some((&entry.name, iter));

                        Some((&entry.name, ret))
                    }
                }
            }
        }

        Iter {
            entries: self.entries.iter(),
            current: None,
        }
    }

    fn entry(&self, n: &Name) -> Option<&Entry> {
        self.entries.iter().find(|Entry { name, .. }| name == n)
    }

    fn entry_mut(&mut self, n: &Name) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|Entry { name, .. }| name == n)
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, value) in self.iter() {
            write!(f, "{}: {}\r\n", name.as_print_str(), value)?;
        }

        Ok(())
    }
}

impl Extend<(Name, BytesStr)> for Headers {
    fn extend<T: IntoIterator<Item = (Name, BytesStr)>>(&mut self, iter: T) {
        for (name, value) in iter {
            self.insert(name, value);
        }
    }
}

#[derive(Debug, PartialEq)]
struct Entry {
    name: Name,
    values: OneOrMore,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OneOrMore {
    One(BytesStr),
    More(Vec<BytesStr>),
}

impl OneOrMore {
    pub fn push(&mut self, value: BytesStr) {
        match self {
            OneOrMore::One(existing_value) => {
                let existing_value = take(existing_value);
                *self = OneOrMore::More(vec![existing_value, value]);
            }
            OneOrMore::More(vec) => vec.push(value),
        }
    }

    fn decode<H: DecodeValues>(&self, name: Name, parser: Parser) -> Result<H, HeaderError> {
        match &self {
            OneOrMore::One(v) => H::decode(parser, &mut once(v)),
            OneOrMore::More(v) => H::decode(parser, &mut v.iter()),
        }
        .map(|(_, h)| h)
        .map_err(|err| HeaderError::malformed(name, err))
    }
}

impl Extend<BytesStr> for OneOrMore {
    fn extend<T: IntoIterator<Item = BytesStr>>(&mut self, iter: T) {
        match self {
            OneOrMore::One(value) => {
                let mut vec = Vec::from_iter(iter);

                if !vec.is_empty() {
                    vec.insert(0, take(value));
                    *self = OneOrMore::More(vec)
                }
            }
            OneOrMore::More(vec) => vec.extend(iter),
        }
    }
}

fn remove_where<T, F>(vec: &mut Vec<T>, f: F) -> Option<T>
where
    F: Fn(&T) -> bool,
{
    vec.iter().position(f).map(|i| vec.remove(i))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::header::typed::MaxForwards;

    #[test]
    fn header_insert() {
        let mut headers = Headers::new();

        headers.insert_named(&MaxForwards(70));

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(headers.entries[0].name, Name::MAX_FORWARDS);
        assert_eq!(
            headers.entries[0].values,
            OneOrMore::One(BytesStr::from_static("70"))
        );
    }

    #[test]
    fn header_insert2() {
        let mut headers = Headers::new();

        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(headers.entries[0].name, Name::MAX_FORWARDS);
        assert_eq!(
            headers.entries[0].values,
            OneOrMore::One(BytesStr::from_static("70"))
        );
    }

    #[test]
    fn header_insert2_twice() {
        let mut headers = Headers::new();

        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(headers.entries[0].name, Name::MAX_FORWARDS);
        assert_eq!(
            headers.entries[0].values,
            OneOrMore::More(vec![
                BytesStr::from_static("70"),
                BytesStr::from_static("70")
            ])
        );
    }

    #[test]
    fn header_remove() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        assert_eq!(headers.remove(&Name::MAX_FORWARDS).unwrap().len(), 1);

        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        assert_eq!(headers.remove(&Name::MAX_FORWARDS).unwrap().len(), 3);
    }

    #[test]
    fn header_take() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        let max_fwd: MaxForwards = headers.take_named().unwrap();

        assert!(headers.entries.is_empty());
        assert_eq!(max_fwd.0, 70);
    }

    #[test]
    fn header_get() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        let max_fwd: MaxForwards = headers.get_named().unwrap();

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(max_fwd.0, 70);
    }

    #[test]
    fn header_get_multiple() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("120"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("140"));

        let max_fwd: Vec<MaxForwards> = headers.get_named().unwrap();

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(max_fwd[0].0, 70);
        assert_eq!(max_fwd[1].0, 120);
        assert_eq!(max_fwd[2].0, 140);
    }

    #[test]
    fn header_edit() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        headers
            .edit_named(|max_fwd: &mut MaxForwards| max_fwd.0 = 120)
            .unwrap();

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(
            headers.entries[0].values,
            OneOrMore::One(BytesStr::from_static("120"))
        );
    }

    #[test]
    fn header_clone_into() {
        let mut headers1 = Headers::new();
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        let mut headers2 = Headers::new();
        headers2.insert(Name::MAX_FORWARDS, BytesStr::from_static("80"));

        headers1
            .clone_into(&mut headers2, Name::MAX_FORWARDS)
            .unwrap();

        assert_eq!(headers1.entries.len(), 1);
        assert_eq!(headers2.entries.len(), 1);

        assert_eq!(
            headers2.entries[0].values,
            OneOrMore::More(vec![
                BytesStr::from_static("80"),
                BytesStr::from_static("70")
            ])
        )
    }

    #[test]
    fn header_clone_into_many() {
        let mut headers1 = Headers::new();
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("80"));

        let mut headers2 = Headers::new();
        headers2.insert(Name::MAX_FORWARDS, BytesStr::from_static("90"));

        headers1
            .clone_into(&mut headers2, Name::MAX_FORWARDS)
            .unwrap();

        assert_eq!(headers1.entries.len(), 1);
        assert_eq!(headers2.entries.len(), 1);

        assert_eq!(
            headers2.entries[0].values,
            OneOrMore::More(vec![
                BytesStr::from_static("90"),
                BytesStr::from_static("70"),
                BytesStr::from_static("80")
            ])
        )
    }

    #[test]
    fn header_drain_into() {
        let mut headers1 = Headers::new();
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        let mut headers2 = Headers::new();
        headers2.insert(Name::MAX_FORWARDS, BytesStr::from_static("80"));

        headers1.drain_into(&mut headers2);

        assert_eq!(headers1.entries.len(), 0);
        assert_eq!(headers2.entries.len(), 1);

        assert_eq!(
            headers2.entries[0].values,
            OneOrMore::More(vec![
                BytesStr::from_static("80"),
                BytesStr::from_static("70")
            ])
        )
    }

    #[test]
    fn header_drain_into_many() {
        let mut headers1 = Headers::new();
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers1.insert(Name::MAX_FORWARDS, BytesStr::from_static("80"));

        let mut headers2 = Headers::new();
        headers2.insert(Name::MAX_FORWARDS, BytesStr::from_static("90"));

        headers1.drain_into(&mut headers2);

        assert_eq!(headers1.entries.len(), 0);
        assert_eq!(headers2.entries.len(), 1);

        assert_eq!(
            headers2.entries[0].values,
            OneOrMore::More(vec![
                BytesStr::from_static("90"),
                BytesStr::from_static("70"),
                BytesStr::from_static("80")
            ])
        )
    }

    #[test]
    fn header_iter() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        headers.insert(
            Name::VIA,
            BytesStr::from_static("SIP/2.0/UDP 192.168.123.222;branch=123abc"),
        );

        headers.insert(Name::CALL_ID, BytesStr::from_static("abc123"));

        headers.insert(
            Name::VIA,
            BytesStr::from_static("SIP/2.0/UDP 192.168.123.223;branch=1234ab"),
        );

        let mut iter = headers.iter();

        let (name, value) = iter.next().unwrap();
        assert_eq!(name, &Name::MAX_FORWARDS);
        assert_eq!(value, "70");

        let (name, value) = iter.next().unwrap();
        assert_eq!(name, &Name::VIA);
        assert_eq!(value, "SIP/2.0/UDP 192.168.123.222;branch=123abc");

        let (name, value) = iter.next().unwrap();
        assert_eq!(name, &Name::VIA);
        assert_eq!(value, "SIP/2.0/UDP 192.168.123.223;branch=1234ab");

        let (name, value) = iter.next().unwrap();
        assert_eq!(name, &Name::CALL_ID);
        assert_eq!(value, "abc123");

        assert!(iter.next().is_none());
    }
}
