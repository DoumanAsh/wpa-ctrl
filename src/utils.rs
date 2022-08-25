pub fn split<const N: usize>(text: &str, ch: char) -> Option<[&str; N]> {
    let mut count = 0;
    let mut result = [""; N];

    for part in text.split(ch) {
        if let Some(elem) = result.get_mut(count) {
            *elem = part.trim();
            count += 1;
        } else {
            return None;
        }
    }

    if count != N {
        None
    } else {
        Some(result)
    }
}
