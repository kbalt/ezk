use super::HeaderError;
use crate::header::name::Name;
use crate::header::Header;
use crate::parse::Parser;
use bytesstr::BytesStr;
use std::iter::once;
use std::iter::FromIterator;
use std::mem::take;
use std::{fmt, slice};

/// Headers is simple container for SIP-Message headers.
/// The headers are stored as [BytesStr] under its respective [Name].
///
/// Internally it is a `Vec`-backed multimap to keep insertion order
#[derive(Debug, Default)]
pub struct Headers {
    entries: Vec<Entry>,
}

impl Headers {
    /// Returns a new empty [Headers]
    #[inline]
    pub const fn new() -> Self {
        Headers {
            entries: Vec::new(),
        }
    }

    /// Returns a new empty [Headers] with the specified capacity
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Headers {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Returns if the [Name] of `H`'s [Header] implementation is contain inside the map.
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Headers;
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert!(headers.contains::<Expires>());
    /// ```
    #[inline]
    pub fn contains<H: Header>(&mut self) -> bool {
        self.entries.iter().any(|entry| &entry.name == H::name())
    }

    /// Prints the header into a BytesStr and stores it
    /// (if not already present) at the start of the buffer
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Headers;
    /// use ezk_sip_types::header::typed::{Expires, MaxForwards};
    ///
    /// let mut headers = Headers::new();
    ///
    /// // insert expires header first
    /// headers.insert_type(&Expires(120));
    ///
    /// // insert Max-Forwards in front
    /// headers.insert_type_front(&MaxForwards(70));
    ///
    /// // test order
    /// assert_eq!(headers.to_string(), "Max-Forwards: 70\r\nExpires: 120\r\n");
    /// ```
    #[inline]
    pub fn insert_type_front<H: Header>(&mut self, header: &H) {
        if let Some(Entry { values, .. }) = self.entry_mut(H::name()) {
            header.encode(Default::default(), values);
        } else if let Some(values) = Values::encode(header) {
            self.entries.insert(
                0,
                Entry {
                    name: H::name().clone(),
                    values,
                },
            );
        }
    }

    /// Bypass the requirement for a [Header] implementation and insert a [BytesStr] directly
    /// at the beginning of a message
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Headers;
    ///
    /// let mut headers = Headers::new();
    ///
    /// // insert expires header first
    /// headers.insert("expires", "120");
    ///
    /// // insert Max-Forwards in front
    /// headers.insert_front("max-forwards", "70");
    ///
    /// // test order
    /// assert_eq!(headers.to_string(), "Max-Forwards: 70\r\nExpires: 120\r\n");
    /// ```
    #[inline]
    pub fn insert_front<N, V>(&mut self, name: N, value: V)
    where
        N: Into<Name>,
        V: Into<BytesStr>,
    {
        let name = name.into();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            values.push(value.into());
        } else {
            self.entries.insert(
                0,
                Entry {
                    name,
                    values: Values::One(value.into()),
                },
            );
        }
    }

    /// Prints the header into a BytesStr and stores it.
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Headers;
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// let expires = Expires(120);
    ///
    /// assert!(headers.get::<Expires>().is_err());
    ///
    /// headers.insert_type(&expires);
    ///
    /// assert_eq!(headers.get::<Expires>().unwrap(), expires);
    /// ```
    #[inline]
    pub fn insert_type<H: Header>(&mut self, header: &H) {
        if let Some(Entry { values, .. }) = self.entry_mut(H::name()) {
            header.encode(Default::default(), values);
        } else if let Some(values) = Values::encode(header) {
            self.entries.push(Entry {
                name: H::name().clone(),
                values,
            });
        }
    }

    /// Bypass the requirement for a [Header] implementation and insert a [BytesStr] directly
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// assert!(headers.get::<Expires>().is_err());
    ///
    /// headers.insert("expires", "120");
    ///
    /// assert_eq!(headers.get::<Expires>().unwrap(), Expires(120));
    /// ```
    #[inline]
    pub fn insert<N, V>(&mut self, name: N, value: V)
    where
        N: Into<Name>,
        V: Into<BytesStr>,
    {
        let name = name.into();

        if let Some(Entry { values, .. }) = self.entry_mut(&name) {
            values.push(value.into());
        } else {
            self.entries.push(Entry {
                name,
                values: Values::One(value.into()),
            });
        }
    }

    /// Remove a header using the type parameter `H`.
    ///
    /// If present it returns all [BytesStr]s saved under the [Header]'s name
    ///
    /// To remove a header and parse it into the type `H` use [Headers::take].
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Headers;
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers.remove_type::<Expires>(), Some(vec!["120".into()]));
    /// ```
    #[inline]
    pub fn remove_type<H: Header>(&mut self) -> Option<Vec<BytesStr>> {
        self.remove(H::name())
    }

    /// Remove all headers with the given `name`
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers.remove(&Name::EXPIRES), Some(vec!["120".into()]));
    /// ```
    #[inline]
    pub fn remove(&mut self, name: &Name) -> Option<Vec<BytesStr>> {
        match remove_where(&mut self.entries, |Entry { name: n, .. }| name == n)?.values {
            Values::One(v) => Some(vec![v]),
            Values::Many(v) => Some(v),
        }
    }

    /// Returns a parsed header `H` and removes it from the map.
    ///
    /// If a header is present but errors during parsing th error will be discarded and returns None.
    /// To handle errors use [Headers::try_take]
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert!(headers.take::<Expires>().is_some());
    /// assert!(headers.take::<Expires>().is_none());
    /// ```
    #[inline]
    pub fn take<H: Header>(&mut self) -> Option<H> {
        self.take2(Default::default())
    }

    /// Same as [Headers::take] but with custom parser.
    #[inline]
    pub fn take2<H: Header>(&mut self, parser: Parser) -> Option<H> {
        self.try_take2(parser).map(Result::ok).flatten()
    }

    /// Returns a parsed header `H` and removes it from the map.
    /// Returns `None` instead an HeaderError if header is not present.
    #[inline]
    pub fn try_take<H: Header>(&mut self) -> Option<Result<H, HeaderError>> {
        self.try_take2(Default::default())
    }

    /// Same as [Headers::try_take] but with custom parser.
    #[inline]
    pub fn try_take2<H: Header>(&mut self, parser: Parser) -> Option<Result<H, HeaderError>> {
        remove_where(&mut self.entries, |Entry { name, .. }| name == H::name())
            .map(|Entry { values, .. }| values.decode(parser))
    }

    /// Returns a parsed header `H`.
    ///
    /// If a header is present but errors during parsing th error will be discarded and returns None.
    /// To handle errors use [Headers::try_get]
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers.get::<Expires>().unwrap().0, 120);
    /// ```
    #[inline]
    pub fn get<H: Header>(&self) -> Result<H, HeaderError> {
        self.get2(Default::default())
    }

    /// Same as [Headers::get] but with custom parser.
    #[inline]
    pub fn get2<H: Header>(&self, parser: Parser) -> Result<H, HeaderError> {
        match self.try_get2(parser) {
            Some(res) => res,
            None => Err(HeaderError::missing(H::name().clone())),
        }
    }

    /// Returns a parsed header `H`. Returns `None` instead an HeaderError if header is not present.
    #[inline]
    pub fn try_get<H: Header>(&self) -> Option<Result<H, HeaderError>> {
        self.try_get2(Default::default())
    }

    /// Same as [Headers::try_get] but with custom parser.
    #[inline]
    pub fn try_get2<H: Header>(&self, parser: Parser) -> Option<Result<H, HeaderError>> {
        Some(self.entry(H::name())?.values.decode(parser))
    }

    /// Takes a closure which edits a header.
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers = Headers::new();
    ///
    /// headers.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers.get::<Expires>().unwrap(), Expires(120));
    ///
    /// headers.edit(|expires: &mut Expires| {
    ///     expires.0 = 240;
    /// });
    ///
    /// assert_eq!(headers.get::<Expires>().unwrap(), Expires(240));
    /// ```
    #[inline]
    pub fn edit<H, F>(&mut self, edit: F) -> Result<(), HeaderError>
    where
        H: Header,
        F: FnOnce(&mut H),
    {
        self.edit2(Default::default(), edit)
    }

    /// Same as [Headers::edit] but with custom parser.
    #[inline]
    pub fn edit2<H, F>(&mut self, parser: Parser, edit: F) -> Result<(), HeaderError>
    where
        H: Header,
        F: FnOnce(&mut H),
    {
        let entry = self
            .entry_mut(H::name())
            .ok_or_else(|| HeaderError::missing(H::name().clone()))?;

        let mut header = entry.values.decode(parser)?;

        (edit)(&mut header);

        if let Some(values) = Values::encode(&header) {
            entry.values = values;
        } else {
            self.remove(H::name());
        }

        Ok(())
    }

    /// Clones all headers with `name` into another [Headers].
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers1 = Headers::new();
    /// let mut headers2 = Headers::new();
    ///
    /// headers1.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers1.get::<Expires>().unwrap(), Expires(120));
    /// assert!(headers2.get::<Expires>().is_err());
    ///
    /// headers1.clone_into(&mut headers2, Name::EXPIRES).unwrap();
    ///
    /// assert_eq!(headers2.get::<Expires>().unwrap(), Expires(120));
    /// ```
    #[inline]
    pub fn clone_into(&self, dest: &mut Self, name: Name) -> Result<(), HeaderError> {
        let Entry { values, .. } = self
            .entry(&name)
            .ok_or_else(|| HeaderError::missing(name.clone()))?;

        match values {
            Values::One(val) => {
                dest.insert(name, val.clone());
            }
            Values::Many(values) => {
                for val in values {
                    dest.insert(name.clone(), val.clone());
                }
            }
        }

        Ok(())
    }

    /// Drain all headers into another [Headers].
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::{Headers, Name};
    /// use ezk_sip_types::header::typed::Expires;
    ///
    /// let mut headers1 = Headers::new();
    /// let mut headers2 = Headers::new();
    ///
    /// headers1.insert_type(&Expires(120));
    ///
    /// assert_eq!(headers1.get::<Expires>().unwrap(), Expires(120));
    /// assert!(headers2.get::<Expires>().is_err());
    ///
    /// headers1.drain_into(&mut headers2);
    ///
    /// assert!(headers1.get::<Expires>().is_err());
    /// assert_eq!(headers2.get::<Expires>().unwrap(), Expires(120));
    /// ```
    pub fn drain_into(&mut self, dst: &mut Self) {
        for Entry { name, values } in self.entries.drain(..) {
            match values {
                Values::One(value) => dst.insert(name, value),
                Values::Many(values) => values
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
                    Values::One(val) => Some((&entry.name, val)),
                    Values::Many(values) => {
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
    values: Values,
}

#[derive(Debug, PartialEq)]
enum Values {
    One(BytesStr),
    Many(Vec<BytesStr>),
}

impl Values {
    fn push(&mut self, value: BytesStr) {
        match self {
            Values::One(existing_value) => {
                let existing_value = take(existing_value);
                *self = Values::Many(vec![existing_value, value]);
            }
            Values::Many(vec) => vec.push(value),
        }
    }

    fn decode<H: Header>(&self, parser: Parser) -> Result<H, HeaderError> {
        match &self {
            Values::One(v) => H::decode(parser, &mut once(v)),
            Values::Many(v) => H::decode(parser, &mut v.iter()),
        }
        .map(|(_, h)| h)
        .map_err(|err| HeaderError::malformed(H::name().clone(), err))
    }

    fn encode<H: Header>(header: &H) -> Option<Self> {
        enum ValuesExt {
            Empty,
            One(BytesStr),
            Many(Vec<BytesStr>),
        }

        impl Extend<BytesStr> for ValuesExt {
            fn extend<T: IntoIterator<Item = BytesStr>>(&mut self, iter: T) {
                iter.into_iter().for_each(|value| match self {
                    ValuesExt::Empty => *self = ValuesExt::One(value),
                    ValuesExt::One(bytes) => *self = ValuesExt::Many(vec![take(bytes), value]),
                    ValuesExt::Many(vec) => vec.push(value),
                });
            }
        }

        let mut values_ext = ValuesExt::Empty;

        H::encode(header, Default::default(), &mut values_ext);

        match values_ext {
            ValuesExt::Empty => None,
            ValuesExt::One(value) => Some(Values::One(value)),
            ValuesExt::Many(values) => Some(Values::Many(values)),
        }
    }
}

impl Extend<BytesStr> for Values {
    fn extend<T: IntoIterator<Item = BytesStr>>(&mut self, iter: T) {
        match self {
            Values::One(value) => {
                let mut vec = Vec::from_iter(iter);

                if !vec.is_empty() {
                    vec.insert(0, take(value));
                    *self = Values::Many(vec)
                }
            }
            Values::Many(vec) => vec.extend(iter),
        }
    }
}

fn remove_where<T, F>(vec: &mut Vec<T>, f: F) -> Option<T>
where
    F: Fn(&T) -> bool,
{
    vec.iter().position(|item| f(item)).map(|i| vec.remove(i))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::header::typed::MaxForwards;

    #[test]
    fn header_insert() {
        let mut headers = Headers::new();

        headers.insert_type(&MaxForwards(70));

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(headers.entries[0].name, Name::MAX_FORWARDS);
        assert_eq!(
            headers.entries[0].values,
            Values::One(BytesStr::from_static("70"))
        );
    }

    #[test]
    fn header_insert_twice() {
        let mut headers = Headers::new();

        headers.insert_type(&MaxForwards(70));
        headers.insert_type(&MaxForwards(70));

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(headers.entries[0].name, Name::MAX_FORWARDS);
        assert_eq!(
            headers.entries[0].values,
            Values::Many(vec![
                BytesStr::from_static("70"),
                BytesStr::from_static("70")
            ])
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
            Values::One(BytesStr::from_static("70"))
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
            Values::Many(vec![
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

        let max_fwd: MaxForwards = headers.take().unwrap();

        assert!(headers.entries.is_empty());
        assert_eq!(max_fwd.0, 70);
    }

    #[test]
    fn header_get() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        let max_fwd: MaxForwards = headers.get().unwrap();

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(max_fwd.0, 70);
    }

    #[test]
    fn header_get_multiple() {
        let mut headers = Headers::new();
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("120"));
        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("140"));

        let max_fwd: Vec<MaxForwards> = headers.get().unwrap();

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
            .edit(|max_fwd: &mut MaxForwards| max_fwd.0 = 120)
            .unwrap();

        assert_eq!(headers.entries.len(), 1);
        assert_eq!(
            headers.entries[0].values,
            Values::One(BytesStr::from_static("120"))
        );
    }

    #[test]
    fn header_edit_remove_empty_multiple() {
        let mut headers = Headers::new();

        headers.insert(Name::MAX_FORWARDS, BytesStr::from_static("70"));

        headers
            .edit(|multiple_max_fwd: &mut Vec<MaxForwards>| {
                assert_eq!(multiple_max_fwd.len(), 1);
                multiple_max_fwd.clear();
            })
            .unwrap();

        assert_eq!(headers.entries.len(), 0);
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
            Values::Many(vec![
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
            Values::Many(vec![
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
            Values::Many(vec![
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
            Values::Many(vec![
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
