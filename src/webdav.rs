use quick_xml::{events::Event, Reader, Writer};

pub fn rewrite_propfind_displayname<F>(xml: &[u8], mut map_name: F) -> Vec<u8>
where
    F: FnMut(&str) -> String,
{
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::with_capacity(xml.len() + 64));
    let mut buf = Vec::new();
    let mut in_display_name = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = local_name(e.name().as_ref());
                if local.eq_ignore_ascii_case("displayname") {
                    in_display_name = true;
                }
                let _ = writer.write_event(Event::Start(e));
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                if local.eq_ignore_ascii_case("displayname") {
                    in_display_name = false;
                }
                let _ = writer.write_event(Event::End(e));
            }
            Ok(Event::Text(t)) => {
                if in_display_name {
                    let src = String::from_utf8_lossy(t.as_ref());
                    let mapped = map_name(&src);
                    let escaped = quick_xml::escape::escape(&mapped).into_owned();
                    let _ = writer
                        .write_event(Event::Text(quick_xml::events::BytesText::new(&escaped)));
                } else {
                    let _ = writer.write_event(Event::Text(t));
                }
            }
            Ok(Event::Eof) => break,
            Ok(ev) => {
                let _ = writer.write_event(ev);
            }
            Err(_) => return xml.to_vec(),
        }
        buf.clear();
    }

    writer.into_inner()
}

fn local_name(name: &[u8]) -> String {
    let s = String::from_utf8_lossy(name);
    if let Some((_, tail)) = s.rsplit_once(':') {
        tail.to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_propfind_displayname;

    #[test]
    fn rewrite_displayname_nodes_only() {
        let input = "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:displayname>中文(1)+-</D:displayname><D:href>/dav/a</D:href></D:response></D:multistatus>";
        let out = rewrite_propfind_displayname(input.as_bytes(), |n| format!("X-{n}"));
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-中文(1)+-"));
        assert!(s.contains("<D:href>/dav/a</D:href>"));
    }
}
