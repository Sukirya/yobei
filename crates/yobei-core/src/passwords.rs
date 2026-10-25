//! Password generation and strength estimation.
//!
//! Generation uses the OS RNG with rejection sampling (no modulo bias)
//! and guarantees at least one character from every enabled class.
//!
//! Strength is a transparent heuristic, not zxcvbn: pool-size entropy
//! with explicit penalties for dictionary words (leet-normalized),
//! sequences, repeats and years. It is advisory UI feedback; the report
//! exposes the estimated bits and the warnings so nothing is hidden
//! behind a single score. Known limitation: passphrase-style passwords
//! made of real words are scored by character pool, which flatters them;
//! the dictionary penalty only partly compensates.

use serde::{Deserialize, Serialize};

use crate::keys;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";
const AMBIGUOUS: &str = "Il1O0|`'\"";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
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

/// Uniformly random index in `0..n` via rejection sampling.
fn rand_index(n: usize) -> usize {
    debug_assert!(n > 0 && n <= 256);
    let limit = 256 - (256 % n);
    loop {
        let b = keys::random_bytes(1)[0] as usize;
        if b < limit {
            return b % n;
        }
    }
}

fn pick(chars: &[char]) -> char {
    chars[rand_index(chars.len())]
}

fn class_chars(base: &str, exclude_ambiguous: bool) -> Vec<char> {
    base.chars()
        .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

pub fn generate_password(options: &GeneratorOptions) -> Result<String, String> {
    let mut classes: Vec<Vec<char>> = Vec::new();
    if options.lowercase {
        classes.push(class_chars(LOWER, options.exclude_ambiguous));
    }
    if options.uppercase {
        classes.push(class_chars(UPPER, options.exclude_ambiguous));
    }
    if options.digits {
        classes.push(class_chars(DIGITS, options.exclude_ambiguous));
    }
    if options.symbols {
        classes.push(class_chars(SYMBOLS, options.exclude_ambiguous));
    }
    if classes.is_empty() {
        return Err("enable at least one character class".to_string());
    }
    if options.length < classes.len() {
        return Err("length is shorter than the number of enabled classes".to_string());
    }
    if options.length > 512 {
        return Err("password length is capped at 512".to_string());
    }
    let union: Vec<char> = classes.iter().flatten().copied().collect();
    let mut out: Vec<char> = classes.iter().map(|c| pick(c)).collect();
    while out.len() < options.length {
        out.push(pick(&union));
    }
    // Fisher–Yates shuffle so the guaranteed class characters are not
    // predictably positioned at the front.
    for i in (1..out.len()).rev() {
        let j = rand_index(i + 1);
        out.swap(i, j);
    }
    Ok(out.into_iter().collect())
}

/// A compact built-in wordlist for passphrase generation. (The full EFF
/// large list is the long-term choice; this list keeps the feature
/// self-contained, and the entropy math uses the real list size.)
const WORDS: &[&str] = &[
    "apple", "arrow", "aspen", "atlas", "bacon", "badge", "bagel", "bamboo", "banjo", "barley",
    "basin", "basket", "beacon", "beaver", "berry", "birch", "bishop", "blanket", "blaze", "blend",
    "breeze", "brick", "bridge", "bronze", "brook", "bubble", "bucket", "butter", "cabin", "cable",
    "cactus", "candle", "cannon", "canvas", "canyon", "carpet", "carrot", "castle", "cedar", "chalk",
    "charm", "cherry", "chest", "cider", "cinder", "citrus", "cliff", "clover", "coast", "cobalt",
    "coffee", "comet", "compass", "copper", "coral", "corner", "cosmos", "cotton", "couch", "cougar",
    "coyote", "cradle", "crane", "crater", "cricket", "crystal", "currant", "curtain", "dagger", "daisy",
    "dandelion", "dawn", "delta", "desert", "dew", "diamond", "diesel", "dinner", "dolphin", "donkey",
    "donut", "dove", "dragon", "dream", "drift", "drum", "dune", "dusk", "dusty", "eagle",
    "earth", "echo", "ecology", "edge", "elder", "elm", "ember", "emerald", "engine", "envoy",
    "epoch", "equinox", "estate", "ether", "evening", "falcon", "fable", "fabric", "factor", "fennel",
    "fern", "ferry", "fiddle", "fig", "filter", "finch", "finger", "fir", "flame", "flask",
    "flavor", "fleece", "flight", "flint", "flora", "flour", "flower", "fluent", "foam", "fog",
    "foil", "forest", "forge", "fork", "format", "fortune", "fossil", "foster", "fox", "fragment",
    "frame", "frost", "frozen", "fruit", "fuel", "fuji", "fungus", "galaxy", "gallery", "gambit",
    "garden", "garlic", "garnet", "gather", "gauge", "gazelle", "gear", "gecko", "gem", "gentle",
    "geyser", "ghost", "giant", "ginger", "giraffe", "glacier", "glade", "glass", "glide", "globe",
    "glory", "glove", "glow", "glucose", "glyph", "gnome", "goat", "goblet", "godzilla", "golden",
    "golf", "gondola", "gong", "gooey", "goose", "gopher", "gorilla", "gospel", "gossip", "gothic",
    "gourd", "gourmet", "govern", "gown", "graffiti", "graft", "grain", "grant", "grape", "graph",
    "grass", "gravity", "graze", "great", "greed", "green", "grid", "grief", "grill", "grimace",
];

pub fn generate_passphrase(word_count: usize, separator: &str) -> Result<String, String> {
    if word_count == 0 || word_count > 32 {
        return Err("word count must be 1..=32".to_string());
    }
    let words: Vec<&str> = (0..word_count)
        .map(|_| WORDS[rand_index(WORDS.len())])
        .collect();
    Ok(words.join(separator))
}

/// Entropy of a passphrase from this module's wordlist, for display.
pub fn passphrase_entropy_bits(word_count: usize) -> f64 {
    word_count as f64 * (WORDS.len() as f64).log2()
}

#[derive(Debug, Clone, Serialize)]
pub struct StrengthReport {
    pub entropy_bits: f64,
    /// 0 (very weak) ..= 4 (excellent).
    pub score: u8,
    pub warnings: Vec<String>,
    /// Rough offline-crack time at 10^10 guesses/second, humanized.
    pub offline_crack_estimate: String,
}

const COMMON_WORDS: &[&str] = &[
    "password", "qwerty", "letmein", "admin", "welcome", "login", "master", "dragon", "football",
    "monkey", "shadow", "superman", "michael", "ninja", "mustang", "charlie", "jordan", "taylor",
    "computer", "michelle", "jessica", "pepper", "iloveyou", "princess", "secret", "summer",
    "winter", "hello", "freedom", "whatever", "starwars", "trustno1", "pokemon", "naruto",
    "sunshine", "ashley", "bailey", "passw0rd", "hunter", "buster", "soccer", "batman", "andrew",
    "joshua", "daniel", "thomas", "george", "hannah", "purple", "orange", "banana", "monkey123",
];

fn leet_normalize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn humanize_seconds(seconds: f64) -> String {
    if seconds < 1.0 {
        return "瞬间".to_string();
    }
    if seconds < 60.0 {
        return format!("{seconds:.0} 秒");
    }
    let minutes = seconds / 60.0;
    if minutes < 60.0 {
        return format!("{minutes:.0} 分钟");
    }
    let hours = minutes / 60.0;
    if hours < 24.0 {
        return format!("{hours:.0} 小时");
    }
    let days = hours / 24.0;
    if days < 365.0 {
        return format!("{days:.0} 天");
    }
    let years = days / 365.0;
    if years < 1e6 {
        return format!("{years:.0} 年");
    }
    if years < 1e9 {
        return format!("{:.0} 百万年", years / 1e6);
    }
    "宇宙年龄级别".to_string()
}

pub fn password_strength(password: &str) -> StrengthReport {
    let mut warnings: Vec<String> = Vec::new();
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return StrengthReport {
            entropy_bits: 0.0,
            score: 0,
            warnings: vec!["密码为空".to_string()],
            offline_crack_estimate: "瞬间".to_string(),
        };
    }
    let mut pool: usize = 0;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars.iter().any(|c| !c.is_alphanumeric() && c.is_ascii()) {
        pool += 33;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100;
    }
    let pool = pool.max(2) as f64;
    let mut bits = chars.len() as f64 * pool.log2();

    // Dictionary penalty (leet-normalized so "P@ssw0rd" does not pass).
    let normalized = leet_normalize(password);
    for word in COMMON_WORDS {
        if normalized == *word {
            bits = bits.min(8.0);
            warnings.push("这是最常见的密码之一".to_string());
            break;
        }
        if normalized.contains(word) {
            bits -= 14.0;
            warnings.push(format!("包含常见词「{word}」"));
            break;
        }
    }

    // Sequence penalty: ascending/descending runs of 4+.
    let mut run = 1i32;
    let mut prev_diff = 0i32;
    let mut sequences = 0;
    for w in chars.windows(2) {
        let diff = w[1] as i32 - w[0] as i32;
        if (diff == 1 || diff == -1) && diff == prev_diff {
            run += 1;
        } else if diff == 1 || diff == -1 {
            run = 2;
        } else {
            run = 1;
        }
        if run == 4 {
            sequences += 1;
        }
        prev_diff = diff;
    }
    if sequences > 0 {
        bits -= 8.0 * sequences as f64;
        warnings.push("包含连续序列（如 abcd / 1234）".to_string());
    }

    // Repeat penalty: same char 3+ times in a row.
    let mut rep = 1;
    let mut has_repeat = false;
    for w in chars.windows(2) {
        if w[0] == w[1] {
            rep += 1;
            if rep == 3 {
                has_repeat = true;
            }
        } else {
            rep = 1;
        }
    }
    if has_repeat {
        bits -= 6.0;
        warnings.push("包含重复字符（如 aaa）".to_string());
    }

    // Year penalty.
    let digits_only: String = chars.iter().filter(|c| c.is_ascii_digit()).collect();
    for w in digits_only.as_bytes().windows(4) {
        let year = std::str::from_utf8(w).unwrap_or("");
        if let Ok(y) = year.parse::<u32>() {
            if (1950..=2030).contains(&y) {
                bits -= 6.0;
                warnings.push("包含年份".to_string());
                break;
            }
        }
    }

    let bits = bits.max(0.0);
    let score = if bits < 28.0 {
        0
    } else if bits < 40.0 {
        1
    } else if bits < 60.0 {
        2
    } else if bits < 90.0 {
        3
    } else {
        4
    };
    let guesses = 2f64.powf((bits - 1.0).max(0.0));
    StrengthReport {
        entropy_bits: bits,
        score,
        warnings,
        offline_crack_estimate: humanize_seconds(guesses / 1e10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_respects_options() {
        let opts = GeneratorOptions { length: 24, symbols: false, ..GeneratorOptions::default() };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(!pw.chars().any(|c| SYMBOLS.contains(c)));

        let digits_only = GeneratorOptions {
            length: 6,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pin = generate_password(&digits_only).unwrap();
        assert!(pin.chars().all(|c| c.is_ascii_digit()));

        let no_amb = generate_password(&GeneratorOptions {
            length: 64,
            exclude_ambiguous: true,
            ..GeneratorOptions::default()
        })
        .unwrap();
        assert!(!no_amb.chars().any(|c| AMBIGUOUS.contains(c)));

        assert!(generate_password(&GeneratorOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..GeneratorOptions::default()
        })
        .is_err());
    }

    #[test]
    fn passphrase_shape_and_entropy() {
        let phrase = generate_passphrase(5, "-").unwrap();
        assert_eq!(phrase.split('-').count(), 5);
        // 210-word list ≈ 7.7 bits/word → 5 words ≈ 38.6 bits.
        assert!(passphrase_entropy_bits(5) > 35.0);
        assert!(generate_passphrase(0, "-").is_err());
    }

    #[test]
    fn strength_ordering_and_warnings() {
        assert_eq!(password_strength("123456").score, 0);
        assert_eq!(password_strength("password").score, 0);
        assert_eq!(password_strength("P@ssw0rd").score, 0); // leet dictionary hit
        let seq = password_strength("abcd1234XYZ!");
        assert!(seq.warnings.iter().any(|w| w.contains("序列")));
        let strong = generate_password(&GeneratorOptions::default()).unwrap();
        let report = password_strength(&strong);
        assert!(report.score >= 3, "generated default should be strong: {report:?}");
        assert!(report.entropy_bits > 90.0);
        let weak = password_strength("abc");
        assert!(weak.entropy_bits < report.entropy_bits);
    }
}
