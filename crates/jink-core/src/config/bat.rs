//! Extracts the `winws.exe` argument list from a zapret-discord-youtube
//! strategy file (`general*.bat`).
//!
//! Handles exactly what those files use: `^` line continuations, `%NAME%`
//! variables supplied by the caller (`BIN`, `LISTS`, `GameFilterTCP`,
//! `GameFilterUDP`), double-quoted arguments, and `^` escapes such as `^!`.
//! It is not a general `cmd.exe` interpreter.

use std::collections::HashMap;
use std::hash::BuildHasher;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatError {
    #[error("no `winws.exe` command line found")]
    NoWinwsLine,
    #[error("variable %{0}% is not defined")]
    UnknownVariable(String),
    #[error("unterminated %variable%")]
    UnterminatedVariable,
    #[error("unterminated double quote")]
    UnterminatedQuote,
}

/// The arguments after `winws.exe`, with variables expanded and quotes
/// removed.
///
/// # Errors
/// See [`BatError`].
pub fn winws_args<S: BuildHasher>(
    bat: &str,
    vars: &HashMap<&str, &str, S>,
) -> Result<Vec<String>, BatError> {
    // A trailing caret joins the next line onto this one.
    let joined = bat.replace("^\r\n", "").replace("^\n", "");
    let line = joined
        .lines()
        .find(|l| l.contains("winws.exe"))
        .ok_or(BatError::NoWinwsLine)?;
    let (_, after) = line
        .split_once("winws.exe\"")
        .ok_or(BatError::NoWinwsLine)?;
    tokenize(&expand(after, vars)?)
}

fn expand<S: BuildHasher>(text: &str, vars: &HashMap<&str, &str, S>) -> Result<String, BatError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once('%') {
        out.push_str(before);
        let (name, tail) = after
            .split_once('%')
            .ok_or(BatError::UnterminatedVariable)?;
        let value = vars
            .get(name)
            .ok_or_else(|| BatError::UnknownVariable(name.to_owned()))?;
        out.push_str(value);
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

fn tokenize(text: &str) -> Result<Vec<String>, BatError> {
    #[derive(Default)]
    struct State {
        tokens: Vec<String>,
        current: Option<String>,
        quoted: bool,
        escaped: bool,
    }
    let end = text.chars().try_fold(State::default(), |mut s, ch| {
        if s.escaped {
            s.current.get_or_insert_with(String::new).push(ch);
            s.escaped = false;
        } else if ch == '"' {
            s.quoted = !s.quoted;
            s.current.get_or_insert_with(String::new);
        } else if ch == '^' && !s.quoted {
            s.escaped = true;
        } else if ch.is_whitespace() && !s.quoted {
            if let Some(token) = s.current.take() {
                s.tokens.push(token);
            }
        } else {
            s.current.get_or_insert_with(String::new).push(ch);
        }
        Ok::<_, BatError>(s)
    })?;
    if end.quoted {
        return Err(BatError::UnterminatedQuote);
    }
    Ok(end.tokens.into_iter().chain(end.current).collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{BatError, winws_args};

    #[test]
    fn continuation_variables_quotes_and_carets() {
        let bat = "@echo off\r\nset x=1\r\nstart \"t: %~n0\" /min \"%BIN%winws.exe\" --a=1 ^\r\n--hostlist=\"%LISTS%l s.txt\" --new ^\r\n--fake=^!\r\necho done\r\n";
        let vars = HashMap::from([("BIN", "bin/"), ("LISTS", "lists/")]);
        assert_eq!(
            winws_args(bat, &vars).unwrap(),
            vec!["--a=1", "--hostlist=lists/l s.txt", "--new", "--fake=!"]
        );
    }

    #[test]
    fn errors() {
        let vars = HashMap::from([("BIN", "bin/")]);
        assert_eq!(winws_args("echo hi", &vars), Err(BatError::NoWinwsLine));
        assert_eq!(
            winws_args("\"%BIN%winws.exe\" --x=%NOPE%", &vars),
            Err(BatError::UnknownVariable("NOPE".into()))
        );
        assert_eq!(
            winws_args("\"%BIN%winws.exe\" --x=\"open", &vars),
            Err(BatError::UnterminatedQuote)
        );
    }
}
