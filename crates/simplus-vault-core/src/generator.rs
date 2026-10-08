//! Password and passphrase generation, plus strength estimation.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Symbols accepted by virtually every site; quotes, backslash and space are left out.
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "Il1O0o|";

pub const MAX_LENGTH: usize = 256;
pub const MAX_WORDS: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("select at least one character type")]
    NoCharacterClasses,
    #[error("length must be between {min} and {MAX_LENGTH}")]
    InvalidLength { min: usize },
    #[error("word count must be between 3 and {MAX_WORDS}")]
    InvalidWordCount,
    #[error("operating system random number generator failed")]
    Rng,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leaves out look-alike characters such as `l`, `1`, `O` and `0`.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    /// Appends a random digit to one of the words.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self { words: 5, separator: "-".into(), capitalize: true, include_number: true }
    }
}

/// Uniform random integer in `0..bound` without modulo bias.
fn random_below(bound: usize) -> Result<usize, GeneratorError> {
    assert!(bound > 0);
    let bound = bound as u64;
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let x = getrandom::u64().map_err(|_| GeneratorError::Rng)?;
        if x < zone {
            return Ok((x % bound) as usize);
        }
    }
}

fn pick(chars: &[char]) -> Result<char, GeneratorError> {
    Ok(chars[random_below(chars.len())?])
}

/// Generates a random password containing at least one character of every selected class.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>, GeneratorError> {
    let classes: Vec<Vec<char>> =
        [(opts.lowercase, LOWER), (opts.uppercase, UPPER), (opts.digits, DIGITS), (opts.symbols, SYMBOLS)]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, set)| {
                set.chars().filter(|c| !opts.exclude_ambiguous || !AMBIGUOUS.contains(*c)).collect()
            })
            .collect();
    if classes.is_empty() {
        return Err(GeneratorError::NoCharacterClasses);
    }
    if opts.length < classes.len().max(4) || opts.length > MAX_LENGTH {
        return Err(GeneratorError::InvalidLength { min: classes.len().max(4) });
    }
    let all: Vec<char> = classes.concat();

    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(opts.length));
    for class in &classes {
        chars.push(pick(class)?);
    }
    while chars.len() < opts.length {
        chars.push(pick(&all)?);
    }
    // Fisher-Yates so the guaranteed characters are not always at the front.
    for i in (1..chars.len()).rev() {
        let j = random_below(i + 1)?;
        chars.swap(i, j);
    }
    Ok(Zeroizing::new(chars.iter().collect()))
}

/// Generates a passphrase from the EFF large wordlist (12.9 bits of entropy per word).
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>, GeneratorError> {
    if !(3..=MAX_WORDS).contains(&opts.words) {
        return Err(GeneratorError::InvalidWordCount);
    }
    let list = eff_wordlist::large::LIST;
    let mut words: Vec<Zeroizing<String>> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let word = list[random_below(list.len())?].1;
        let word = if opts.capitalize {
            let mut c = word.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
        } else {
            word.to_owned()
        };
        words.push(Zeroizing::new(word));
    }
    if opts.include_number {
        let i = random_below(words.len())?;
        let digit = char::from(b'0' + random_below(10)? as u8);
        words[i].push(digit);
    }
    let parts: Vec<&str> = words.iter().map(|w| w.as_str()).collect();
    Ok(Zeroizing::new(parts.join(&opts.separator)))
}

/// Password strength as estimated by zxcvbn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strength {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    pub label: &'static str,
    /// Estimated time to crack offline against a slow hash, e.g. "3 centuries".
    pub crack_time: String,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// Estimates strength. `user_inputs` (e.g. the username or site) are penalised if reused.
pub fn strength(password: &str, user_inputs: &[&str]) -> Strength {
    // zxcvbn is super-linear in length; the first 128 characters decide anyway.
    let truncated: String = password.chars().take(128).collect();
    let entropy = zxcvbn::zxcvbn(&truncated, user_inputs);
    let score: u8 = entropy.score().into();
    let label = match score {
        0 => "Very weak",
        1 => "Weak",
        2 => "Fair",
        3 => "Strong",
        _ => "Very strong",
    };
    let feedback = entropy.feedback();
    Strength {
        score,
        label,
        crack_time: entropy.crack_times().offline_slow_hashing_1e4_per_second().to_string(),
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_every_selected_class() {
        let opts = PasswordOptions { length: 8, ..Default::default() };
        for _ in 0..200 {
            let pw = generate_password(&opts).unwrap();
            assert_eq!(pw.chars().count(), 8);
            assert!(pw.chars().any(|c| LOWER.contains(c)));
            assert!(pw.chars().any(|c| UPPER.contains(c)));
            assert!(pw.chars().any(|c| DIGITS.contains(c)));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn respects_class_selection_and_ambiguity() {
        let opts = PasswordOptions {
            length: 64,
            lowercase: false,
            uppercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let pw = generate_password(&opts).unwrap();
        assert!(
            pw.chars().all(|c| (UPPER.contains(c) || DIGITS.contains(c)) && !AMBIGUOUS.contains(c)),
            "{}",
            *pw
        );
    }

    #[test]
    fn invalid_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(generate_password(&none).unwrap_err(), GeneratorError::NoCharacterClasses);
        let short = PasswordOptions { length: 3, ..Default::default() };
        assert!(matches!(generate_password(&short), Err(GeneratorError::InvalidLength { .. })));
        let long = PasswordOptions { length: MAX_LENGTH + 1, ..Default::default() };
        assert!(matches!(generate_password(&long), Err(GeneratorError::InvalidLength { .. })));
        assert_eq!(
            generate_passphrase(&PassphraseOptions { words: 2, ..Default::default() }).unwrap_err(),
            GeneratorError::InvalidWordCount
        );
    }

    #[test]
    fn passwords_are_random() {
        let opts = PasswordOptions::default();
        assert_ne!(*generate_password(&opts).unwrap(), *generate_password(&opts).unwrap());
    }

    #[test]
    fn passphrase_shape() {
        let opts = PassphraseOptions::default();
        let phrase = generate_passphrase(&opts).unwrap();
        let words: Vec<&str> = phrase.split('-').collect();
        assert_eq!(words.len(), 5);
        assert!(words.iter().all(|w| w.chars().next().unwrap().is_uppercase()));
        assert_eq!(phrase.chars().filter(char::is_ascii_digit).count(), 1);
    }

    #[test]
    fn random_below_covers_range() {
        let mut seen = [false; 5];
        for _ in 0..500 {
            seen[random_below(5).unwrap()] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn strength_scores() {
        let weak = strength("password1", &[]);
        assert!(weak.score <= 1, "{weak:?}");
        let strong = strength("correct-Horse-battery-staple-9-unusual", &[]);
        assert_eq!(strong.score, 4, "{strong:?}");
        assert!(strength("octocat2026", &["octocat"]).score < strength("octocat2026", &[]).score.max(1) + 1);
    }
}
