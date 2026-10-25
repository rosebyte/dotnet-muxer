//! Tests of the versioned configuration store and the shared application lock.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::temp_dir;
use muxlet::config::{self, Commit, Document, ErrorKind, Fingerprint, HomeLock, Transaction};
use muxlet::home;
use serde_json::{Value, json};

const EMPTY: &str = "{\"schemaVersion\": 1, \"extensions\": {}}";

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let directory = temp_dir();
    let home = directory.path().join("application home");
    (directory, home)
}

fn put(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn configuration(home: &Path) -> PathBuf {
    home::configuration(home)
}

fn snapshots(home: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(config::journal_directory(home)) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with("configuration-") && name.ends_with(".json")
        })
        .collect();
    paths.sort();
    paths
}

fn staging_leftovers(directory: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".configuration-") || name.starts_with(".snapshot-"))
        .collect()
}

fn assert_nothing_staged(home: &Path) {
    assert_eq!(staging_leftovers(home), Vec::<String>::new());
    assert_eq!(
        staging_leftovers(&config::journal_directory(home)),
        Vec::<String>::new()
    );
}

fn add_section(name: &'static str, value: Value) -> impl FnOnce(&mut Document) {
    move |document| {
        document.set_extension(name, value);
    }
}

fn keys(value: &Value) -> Vec<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

/// The exact digits a number is held as; fails for anything that is not one.
fn digits(value: &Value) -> &str {
    value
        .as_number()
        .unwrap_or_else(|| panic!("{value:?} is not a number"))
        .as_str()
}

#[allow(clippy::permissions_set_readonly_false)]
fn make_writable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

fn symlink_file(original: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(original, link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        // Creating links needs Developer Mode or elevation; skip without it.
        std::os::windows::fs::symlink_file(original, link).is_ok()
    }
}

fn symlink_dir(original: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(original, link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(original, link).is_ok()
    }
}

#[test]
fn paths_follow_the_published_layout() {
    let home = Path::new("/some/application home");
    assert_eq!(
        config::lock_path(home),
        home.join("metadata").join("application.lock")
    );
    assert_eq!(config::journal_directory(home), home.join("journal"));
    assert_eq!(configuration(home), home.join("configuration.json"));
    assert_eq!(config::SCHEMA_VERSION, 1);
}

#[test]
fn a_missing_configuration_is_the_empty_envelope_and_is_created_only_on_commit() {
    let (_directory, home) = workspace();

    let lock = HomeLock::acquire(&home).unwrap();
    assert!(config::lock_path(&home).is_file());
    let mut transaction = Transaction::begin(&lock).unwrap();
    assert_eq!(transaction.original_fingerprint(), Fingerprint::Missing);
    assert_eq!(transaction.document(), &Document::new());
    assert_eq!(transaction.path(), configuration(&home));
    assert!(
        !configuration(&home).exists(),
        "starting must not create it"
    );

    transaction
        .document_mut()
        .set_extension("sdks", json!({"schemaVersion": 3, "roots": []}));
    assert_eq!(transaction.commit().unwrap(), Commit::Created);

    assert_eq!(
        fs::read_to_string(configuration(&home)).unwrap(),
        "{\n  \"schemaVersion\": 1,\n  \"extensions\": {\n    \"sdks\": {\n      \
         \"schemaVersion\": 3,\n      \"roots\": []\n    }\n  }\n}\n"
    );
    assert!(snapshots(&home).is_empty(), "nothing was replaced");
    assert_nothing_staged(&home);
}

#[test]
fn committing_an_untouched_missing_configuration_creates_the_empty_envelope() {
    let (_directory, home) = workspace();
    assert_eq!(config::update(&home, |_| {}).unwrap(), Commit::Created);
    assert_eq!(
        Document::parse(&fs::read(configuration(&home)).unwrap()).unwrap(),
        Document::new()
    );
}

#[test]
fn reading_never_creates_files_and_a_missing_file_reads_as_the_empty_envelope() {
    let (_directory, home) = workspace();
    assert_eq!(config::read(&home).unwrap(), Document::new());
    assert!(!home.exists(), "a read must not create anything");
}

#[test]
fn unrelated_json_is_preserved_opaquely_including_numeric_precision_and_order() {
    let (_directory, home) = workspace();
    let original = r#"{
        "extensions": {
            "other": {
                "big": 123456789012345678901234567890,
                "tiny": 0.1000000000000000055511151231257827,
                "trailing": 1.50,
                "negative zero": -0,
                "exponent": 1E+2,
                "nested": [1, 2.0, {"deep": null, "z": true}, [], {}],
                "text": "\u00e9\ud83d\ude00 \/ \"quoted\"",
                "": "empty key"
            },
            "sdks": {"tracked": ["a"]}
        },
        "future": {"keep": ["me", 1.0e-7]},
        "schemaVersion": 1,
        "note": "top-level"
    }"#;
    put(&configuration(&home), original);

    config::update(&home, add_section("sdks", json!({"tracked": ["a", "b"]}))).unwrap();

    let text = fs::read_to_string(configuration(&home)).unwrap();
    for member in [
        "\"big\": 123456789012345678901234567890",
        "\"tiny\": 0.1000000000000000055511151231257827",
        "\"trailing\": 1.50",
        "\"negative zero\": -0",
        "\"exponent\": 1e+2",
        "\"keep\": [\n      \"me\",\n      1.0e-7\n    ]",
    ] {
        assert!(text.contains(member), "{member} was not kept in\n{text}");
    }

    let before: Value = serde_json::from_str(original).unwrap();
    let after: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(after["extensions"]["other"], before["extensions"]["other"]);
    assert_eq!(after["future"], before["future"]);
    assert_eq!(after["note"], before["note"]);
    assert_eq!(after["extensions"]["sdks"], json!({"tracked": ["a", "b"]}));
    assert_eq!(
        keys(&after),
        ["extensions", "future", "schemaVersion", "note"]
    );
    assert_eq!(keys(&after["extensions"]), ["other", "sdks"]);
    assert_eq!(
        keys(&after["extensions"]["other"]),
        keys(&before["extensions"]["other"])
    );
}

const NUMBER_KEY: &str = "$serde_json::private::Number";
const RAW_VALUE_KEY: &str = "$serde_json::private::RawValue";

/// A configuration whose extension `other` has the section `section`, beside a
/// section `mine` that an unrelated writer owns.
fn with_other(section: &str) -> String {
    format!(r#"{{"schemaVersion": 1, "extensions": {{"other": {section}, "mine": {{"n": 1}}}}}}"#)
}

/// Reads such a configuration, lets the unrelated writer change its own
/// section, and checks that `other` is exactly `expected` before and after,
/// in memory and in the file that was written. Expected values are built with
/// `json!`, never by parsing, which would be subject to the very confusion
/// that is being checked.
fn assert_survives(label: &str, section: &str, expected: Value) {
    let (_directory, home) = workspace();
    put(&configuration(&home), with_other(section));

    let before = config::read(&home).unwrap_or_else(|error| panic!("{label}: {error}"));
    assert_eq!(before.extension("other"), Some(&expected), "{label}");

    let commit = config::update(&home, add_section("mine", json!({"n": 2})))
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(matches!(commit, Commit::Replaced { .. }), "{label}");

    let after = config::read(&home).unwrap();
    assert_eq!(after.extension("other"), Some(&expected), "{label}");
    assert_eq!(after.extension("mine"), Some(&json!({"n": 2})), "{label}");
    assert_eq!(
        after.extensions().keys().cloned().collect::<Vec<_>>(),
        ["other", "mine"],
        "{label}"
    );

    // What was written reads back as the same document, and writing that
    // document again produces the same bytes.
    let bytes = fs::read(configuration(&home)).unwrap();
    assert_eq!(Document::parse(&bytes).unwrap(), after, "{label}");
    assert_eq!(
        Document::parse(&bytes).unwrap().to_bytes(),
        bytes,
        "{label}"
    );
    assert_nothing_staged(&home);
}

#[test]
fn an_object_keyed_like_serde_jsons_number_marker_is_not_turned_into_a_number() {
    // The reported case: nothing but the marker key with a numeric string.
    let (_directory, home) = workspace();
    let original =
        r#"{"schemaVersion":1,"extensions":{"other":{"$serde_json::private::Number":"123"}}}"#;
    put(&configuration(&home), original);

    let document = Document::parse(original.as_bytes()).unwrap();
    let section = document.extension("other").unwrap();
    assert!(
        section.is_object() && !section.is_number(),
        "read as {section:?}"
    );
    assert_eq!(section, &json!({"$serde_json::private::Number": "123"}));

    // An unrelated writer changes only its own section.
    let commit = config::update(&home, add_section("mine", json!({"n": 1}))).unwrap();
    let Commit::Replaced { snapshot } = commit else {
        panic!("expected a replacement, got {commit:?}");
    };
    assert_eq!(
        fs::read_to_string(configuration(&home)).unwrap(),
        "{\n  \"schemaVersion\": 1,\n  \"extensions\": {\n    \"other\": {\n      \
         \"$serde_json::private::Number\": \"123\"\n    },\n    \"mine\": {\n      \"n\": 1\n    \
         }\n  }\n}\n"
    );
    assert_eq!(fs::read(snapshot).unwrap(), original.as_bytes());
    assert_nothing_staged(&home);
}

#[test]
fn objects_keyed_like_serde_jsons_internal_markers_are_ordinary_objects_in_any_shape() {
    let cases: Vec<(&str, &str, Value)> = vec![
        (
            "number marker first, numeric text",
            r#"{"$serde_json::private::Number": "123"}"#,
            json!({"$serde_json::private::Number": "123"}),
        ),
        (
            "number marker first, more members after it",
            r#"{"$serde_json::private::Number": "123", "after": true}"#,
            json!({"$serde_json::private::Number": "123", "after": true}),
        ),
        (
            "number marker after another member",
            r#"{"before": 1, "$serde_json::private::Number": "123"}"#,
            json!({"before": 1, "$serde_json::private::Number": "123"}),
        ),
        (
            "number marker first, number value",
            r#"{"$serde_json::private::Number": 123}"#,
            json!({"$serde_json::private::Number": 123}),
        ),
        (
            "number marker first, object value",
            r#"{"$serde_json::private::Number": {"inner": [1, 2]}}"#,
            json!({"$serde_json::private::Number": {"inner": [1, 2]}}),
        ),
        (
            "number marker first, array value",
            r#"{"$serde_json::private::Number": [1, "2"]}"#,
            json!({"$serde_json::private::Number": [1, "2"]}),
        ),
        (
            "number marker first, null",
            r#"{"$serde_json::private::Number": null}"#,
            json!({"$serde_json::private::Number": null}),
        ),
        (
            "number marker first, boolean",
            r#"{"$serde_json::private::Number": false}"#,
            json!({"$serde_json::private::Number": false}),
        ),
        (
            "number marker first, text that is no number",
            r#"{"$serde_json::private::Number": "not a number"}"#,
            json!({"$serde_json::private::Number": "not a number"}),
        ),
        (
            "number marker first, empty text",
            r#"{"$serde_json::private::Number": ""}"#,
            json!({"$serde_json::private::Number": ""}),
        ),
        (
            "number marker first, exponent text",
            r#"{"$serde_json::private::Number": "1e400"}"#,
            json!({"$serde_json::private::Number": "1e400"}),
        ),
        (
            "number marker inside arrays",
            r#"[{"$serde_json::private::Number": "1"}, 3, [{"$serde_json::private::Number": "2"}]]"#,
            json!([{"$serde_json::private::Number": "1"}, 3, [{"$serde_json::private::Number": "2"}]]),
        ),
        (
            "number marker deep inside objects",
            r#"{"a": {"b": [{"c": {"$serde_json::private::Number": "9"}}]}}"#,
            json!({"a": {"b": [{"c": {"$serde_json::private::Number": "9"}}]}}),
        ),
        (
            "number marker inside the number marker",
            r#"{"$serde_json::private::Number": {"$serde_json::private::Number": "5"}}"#,
            json!({"$serde_json::private::Number": {"$serde_json::private::Number": "5"}}),
        ),
        (
            "raw value marker first, text",
            r#"{"$serde_json::private::RawValue": "{\"x\": 1}"}"#,
            json!({"$serde_json::private::RawValue": "{\"x\": 1}"}),
        ),
        (
            "raw value marker first, more members",
            r#"{"$serde_json::private::RawValue": 1, "n": 2}"#,
            json!({"$serde_json::private::RawValue": 1, "n": 2}),
        ),
        (
            "raw value marker after another member",
            r#"{"n": 2, "$serde_json::private::RawValue": [1]}"#,
            json!({"n": 2, "$serde_json::private::RawValue": [1]}),
        ),
        (
            "both markers",
            r#"{"$serde_json::private::Number": "1", "$serde_json::private::RawValue": "2"}"#,
            json!({"$serde_json::private::Number": "1", "$serde_json::private::RawValue": "2"}),
        ),
        (
            "marker spelled with an escape",
            r#"{"\u0024serde_json::private::Number": "123"}"#,
            json!({"$serde_json::private::Number": "123"}),
        ),
        (
            "raw value marker spelled with escapes",
            r#"{"\u0024serde_json\u003a\u003aprivate\u003a\u003aRawValue": "x"}"#,
            json!({"$serde_json::private::RawValue": "x"}),
        ),
    ];
    for (label, section, expected) in cases {
        assert_survives(label, section, expected);
    }
}

#[test]
fn marker_keys_with_any_character_unicode_escaped_stay_objects() {
    for key in [NUMBER_KEY, RAW_VALUE_KEY] {
        let mut all_escaped = String::new();
        for (index, byte) in key.bytes().enumerate() {
            let escaped = format!("\\u{byte:04x}");
            all_escaped.push_str(&escaped);
            let partially_escaped = format!("{}{escaped}{}", &key[..index], &key[index + 1..]);
            for (section, expected) in [
                (
                    format!(r#"{{"{partially_escaped}":"123","after":false}}"#),
                    json!({key: "123", "after": false}),
                ),
                (
                    format!(r#"{{"before":false,"{partially_escaped}":"123"}}"#),
                    json!({"before": false, key: "123"}),
                ),
                (
                    format!(r#"[{{"nested":{{"{partially_escaped}":"123"}}}}]"#),
                    json!([{"nested": {key: "123"}}]),
                ),
            ] {
                let document = Document::parse(with_other(&section).as_bytes()).unwrap();
                assert_eq!(document.extension("other"), Some(&expected), "{section}");
                assert_eq!(
                    Document::parse(&document.to_bytes()).unwrap(),
                    document,
                    "{section}"
                );
            }
        }
        assert_survives(
            "fully escaped marker",
            &format!(r#"{{"{all_escaped}":"123"}}"#),
            json!({key: "123"}),
        );
    }
}

#[test]
fn marker_names_are_ordinary_extension_names_and_top_level_members() {
    // An extension that is called by the marker.
    let document = Document::parse(
        br#"{"schemaVersion": 1, "extensions": {"$serde_json::private::Number": "123"}}"#,
    )
    .unwrap();
    assert_eq!(document.extensions().len(), 1);
    assert_eq!(document.extension(NUMBER_KEY), Some(&json!("123")));

    // Top-level members that are called by the markers, the first one first.
    let text = br#"{"$serde_json::private::Number": "7", "schemaVersion": 1, "extensions": {}, "$serde_json::private::RawValue": [8]}"#;
    let document = Document::parse(text).unwrap();
    assert_eq!(document.get(NUMBER_KEY), Some(&json!("7")));
    assert_eq!(document.get(RAW_VALUE_KEY), Some(&json!([8])));
    let bytes = document.to_bytes();
    let written = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        written.find(NUMBER_KEY).unwrap() < written.find("schemaVersion").unwrap(),
        "member order is kept:\n{written}"
    );
    assert_eq!(Document::parse(&bytes).unwrap(), document);

    // And all of it survives an unrelated writer.
    let (_directory, home) = workspace();
    put(&configuration(&home), text);
    config::update(&home, add_section("mine", json!(1))).unwrap();
    let after = config::read(&home).unwrap();
    assert_eq!(after.get(NUMBER_KEY), Some(&json!("7")));
    assert_eq!(after.get(RAW_VALUE_KEY), Some(&json!([8])));
    assert_eq!(after.extension("mine"), Some(&json!(1)));

    // An extension may also be given such a name by its own writer.
    let (_directory, home) = workspace();
    config::update(&home, |document| {
        document.set_extension(NUMBER_KEY, json!({"x": 1}));
        document.set_extension("odd", json!({"$serde_json::private::Number": "123"}));
    })
    .unwrap();
    let written = fs::read_to_string(configuration(&home)).unwrap();
    assert!(
        written.contains("\"odd\": {\n      \"$serde_json::private::Number\": \"123\"\n    }"),
        "{written}"
    );
    let document = config::read(&home).unwrap();
    assert_eq!(document.extension(NUMBER_KEY), Some(&json!({"x": 1})));
    assert_eq!(
        document.extension("odd"),
        Some(&json!({"$serde_json::private::Number": "123"}))
    );
}

#[test]
fn numbers_keep_every_digit_beside_objects_that_look_like_number_markers() {
    let (_directory, home) = workspace();
    put(
        &configuration(&home),
        r#"{
            "schemaVersion": 1,
            "extensions": {
                "other": {
                    "big": 123456789012345678901234567890,
                    "marker": {"$serde_json::private::Number": "1"},
                    "tiny": 0.1000000000000000055511151231257827,
                    "list": [1.50, {"$serde_json::private::Number": "2"}, 1E+2, -0]
                }
            }
        }"#,
    );

    config::update(&home, add_section("mine", json!(1))).unwrap();

    let text = fs::read_to_string(configuration(&home)).unwrap();
    for member in [
        "\"big\": 123456789012345678901234567890,",
        "\"tiny\": 0.1000000000000000055511151231257827,",
        "\"marker\": {\n        \"$serde_json::private::Number\": \"1\"\n      },",
        "1.50,\n        {\n          \"$serde_json::private::Number\": \"2\"\n        },\n        \
         1e+2,\n        -0\n",
    ] {
        assert!(text.contains(member), "{member} was not kept in\n{text}");
    }
    let document = config::read(&home).unwrap();
    let other = document.extension("other").unwrap();
    // Not merely numbers: the very digits that were written, in the form the
    // library keeps them (only the exponent marker is normalised).
    assert_eq!(digits(&other["big"]), "123456789012345678901234567890");
    assert_eq!(
        digits(&other["tiny"]),
        "0.1000000000000000055511151231257827"
    );
    assert_eq!(digits(&other["list"][0]), "1.50");
    assert_eq!(digits(&other["list"][2]), "1e+2");
    assert_eq!(digits(&other["list"][3]), "-0");
    assert!(other["marker"].is_object() && other["list"][1].is_object());
}

#[test]
fn duplicate_marker_keys_are_still_rejected() {
    for text in [
        r#"{"schemaVersion":1,"extensions":{"other":{"$serde_json::private::Number":"1","$serde_json::private::Number":"2"}}}"#,
        r#"{"schemaVersion":1,"extensions":{"other":[{"$serde_json::private::RawValue":1,"$serde_json::private::RawValue":2}]}}"#,
        r#"{"$serde_json::private::Number":"1","schemaVersion":1,"extensions":{},"$serde_json::private::Number":"2"}"#,
        r#"{"schemaVersion":1,"extensions":{"$serde_json::private::Number":1,"$serde_json::private::Number":1}}"#,
        // The same key, spelled two ways.
        r#"{"schemaVersion":1,"extensions":{"other":{"$serde_json::private::Number":"1","\u0024serde_json::private::Number":"2"}}}"#,
    ] {
        let error = Document::parse(text.as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DuplicateKey, "{text}");
    }
}

#[test]
fn nesting_up_to_the_json_librarys_limit_is_read_and_deeper_is_refused() {
    // The root and its "extensions" object are the first two levels.
    let nested = |levels: usize| {
        format!(
            r#"{{"schemaVersion": 1, "extensions": {{"deep": {}{}}}}}"#,
            "[".repeat(levels),
            "]".repeat(levels)
        )
    };
    for levels in [1, 50, 125] {
        let document = Document::parse(nested(levels).as_bytes())
            .unwrap_or_else(|error| panic!("{levels} levels: {error}"));
        assert!(document.extension("deep").unwrap().is_array());
    }
    for levels in [126, 127, 200] {
        let error = Document::parse(nested(levels).as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed, "{levels} levels");
        assert!(error.to_string().contains("recursion limit"), "{error}");
    }
}

#[test]
fn sequential_writers_preserve_each_others_sections_and_snapshot_every_replacement() {
    let (_directory, home) = workspace();
    let path = configuration(&home);

    // One writer knows only "sdks", the next only "build".
    let created = config::update(
        &home,
        add_section("sdks", json!({"schemaVersion": 2, "tracked": ["/a"]})),
    )
    .unwrap();
    assert_eq!(created, Commit::Created);
    let after_first = fs::read(&path).unwrap();

    let second = config::update(&home, add_section("build", json!({"parallel": 4}))).unwrap();
    let Commit::Replaced { snapshot } = second else {
        panic!("expected a replacement, got {second:?}");
    };
    assert_eq!(fs::read(&snapshot).unwrap(), after_first);
    let after_second = fs::read(&path).unwrap();

    let third = config::update(&home, |document| {
        let mut sdks = document.extension("sdks").unwrap().clone();
        sdks["tracked"].as_array_mut().unwrap().push(json!("/b"));
        document.set_extension("sdks", sdks);
    })
    .unwrap();
    assert!(matches!(third, Commit::Replaced { .. }));

    let document = config::read(&home).unwrap();
    assert_eq!(
        document.extension("sdks"),
        Some(&json!({"schemaVersion": 2, "tracked": ["/a", "/b"]}))
    );
    assert_eq!(document.extension("build"), Some(&json!({"parallel": 4})));
    assert_eq!(
        keys(&Value::Object(document.extensions().clone())),
        ["sdks", "build"]
    );

    let mut saved: Vec<Vec<u8>> = snapshots(&home)
        .iter()
        .map(|snapshot| fs::read(snapshot).unwrap())
        .collect();
    saved.sort();
    let mut expected = vec![after_first, after_second];
    expected.sort();
    assert_eq!(saved, expected);
    assert_nothing_staged(&home);
}

#[test]
fn concurrent_writers_are_serialised_by_the_lock_and_lose_no_update() {
    let (_directory, home) = workspace();
    const WRITERS: usize = 8;

    thread::scope(|scope| {
        for writer in 0..WRITERS {
            let home = &home;
            scope.spawn(move || {
                config::update(home, |document| {
                    document.set_extension(&format!("writer-{writer}"), json!(writer));
                })
                .unwrap();
            });
        }
    });

    let document = config::read(&home).unwrap();
    assert_eq!(document.extensions().len(), WRITERS);
    for writer in 0..WRITERS {
        assert_eq!(
            document.extension(&format!("writer-{writer}")),
            Some(&json!(writer))
        );
    }
    // The first commit created the file; each other one replaced a distinct version.
    assert_eq!(snapshots(&home).len(), WRITERS - 1);
    assert_nothing_staged(&home);
}

#[test]
fn the_application_lock_is_exclusive_and_reports_contention() {
    let (_directory, home) = workspace();

    let first = HomeLock::acquire(&home).unwrap();
    assert_eq!(first.path(), config::lock_path(&home));
    assert_eq!(first.home(), home);

    let error = HomeLock::try_acquire(&home).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Busy);
    assert!(error.to_string().contains("application.lock"), "{error}");
    assert_eq!(error.path(), config::lock_path(&home));

    let started = Instant::now();
    let error = HomeLock::acquire_timeout(&home, Duration::from_millis(250)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Busy);
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(started.elapsed() < Duration::from_secs(20));

    drop(first);
    let _second = HomeLock::try_acquire(&home).unwrap();
}

#[test]
fn a_waiting_writer_gets_the_lock_when_the_holder_releases_it() {
    let (_directory, home) = workspace();
    let holder = HomeLock::acquire(&home).unwrap();

    let waited = thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            let started = Instant::now();
            let _lock = HomeLock::acquire_timeout(&home, Duration::from_secs(30)).unwrap();
            started.elapsed()
        });
        thread::sleep(Duration::from_millis(300));
        drop(holder);
        waiter.join().unwrap()
    });
    // The holder released after 300 ms; the lower bound is generous so that a
    // slow thread start-up cannot make this flaky.
    assert!(waited >= Duration::from_millis(100), "{waited:?}");
}

#[test]
fn an_enormous_lock_timeout_waits_instead_of_overflowing() {
    let (_directory, home) = workspace();

    // Uncontended, the lock is simply taken; no deadline can overflow.
    drop(HomeLock::acquire_timeout(&home, Duration::MAX).unwrap());

    // Contended, it waits for the holder, however long that takes.
    let holder = HomeLock::acquire(&home).unwrap();
    let released = AtomicBool::new(false);
    thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            let _lock = HomeLock::acquire_timeout(&home, Duration::MAX).unwrap();
            released.load(Ordering::SeqCst)
        });
        released.store(true, Ordering::SeqCst);
        drop(holder);
        assert!(
            waiter.join().unwrap(),
            "the lock was granted while the holder still held it"
        );
    });
}

#[test]
fn lock_paths_that_are_not_regular_files_are_refused() {
    let (_directory, home) = workspace();
    fs::create_dir_all(config::lock_path(&home)).unwrap();
    let error = HomeLock::try_acquire(&home).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);

    let (directory, home) = workspace();
    let elsewhere = directory.path().join("elsewhere.lock");
    put(&elsewhere, "");
    fs::create_dir_all(home.join("metadata")).unwrap();
    if symlink_file(&elsewhere, &config::lock_path(&home)) {
        let error = HomeLock::try_acquire(&home).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
    }

    let (_directory, home) = workspace();
    put(&home, "a file where the home should be");
    let error = HomeLock::try_acquire(&home).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.to_string().contains("metadata"), "{error}");
}

#[test]
fn a_manual_edit_between_read_and_commit_refuses_the_commit_and_is_never_overwritten() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);

    let lock = HomeLock::acquire(&home).unwrap();
    let mut transaction = Transaction::begin(&lock).unwrap();
    transaction
        .document_mut()
        .set_extension("sdks", json!({"tracked": true}));

    let edited = "{\n \"schemaVersion\": 1,\n \"extensions\": {\"mine\": true}\n}\n";
    put(&path, edited);
    let error = transaction.commit().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Changed);
    assert!(error.to_string().contains("retry"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), edited);
    assert!(snapshots(&home).is_empty());
    assert_nothing_staged(&home);
    drop(lock);

    // Retrying builds on the edit instead of discarding it.
    config::update(&home, add_section("sdks", json!({"tracked": true}))).unwrap();
    let document = config::read(&home).unwrap();
    assert_eq!(document.extension("mine"), Some(&json!(true)));
    assert_eq!(document.extension("sdks"), Some(&json!({"tracked": true})));
}

#[test]
fn an_editor_that_replaces_the_file_by_rename_is_detected() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);

    let lock = HomeLock::acquire(&home).unwrap();
    let mut transaction = Transaction::begin(&lock).unwrap();
    transaction.document_mut().set_extension("sdks", json!(1));

    let replacement = home.join("editor-save.tmp");
    put(
        &replacement,
        "{\"schemaVersion\": 1, \"extensions\": {\"editor\": 1}}",
    );
    fs::rename(&replacement, &path).unwrap();
    let error = transaction.commit().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Changed);
    assert!(fs::read_to_string(&path).unwrap().contains("editor"));
}

#[test]
fn deleting_or_creating_the_file_after_reading_is_a_race_too() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);
    {
        let lock = HomeLock::acquire(&home).unwrap();
        let mut transaction = Transaction::begin(&lock).unwrap();
        transaction.document_mut().set_extension("sdks", json!(1));
        fs::remove_file(&path).unwrap();
        assert_eq!(transaction.commit().unwrap_err().kind(), ErrorKind::Changed);
        assert!(!path.exists(), "a deleted file must not be resurrected");
    }

    let lock = HomeLock::acquire(&home).unwrap();
    let mut transaction = Transaction::begin(&lock).unwrap();
    assert_eq!(transaction.original_fingerprint(), Fingerprint::Missing);
    transaction.document_mut().set_extension("sdks", json!(1));
    put(&path, "someone else was first");
    assert_eq!(transaction.commit().unwrap_err().kind(), ErrorKind::Changed);
    assert_eq!(fs::read_to_string(&path).unwrap(), "someone else was first");
}

#[test]
fn rewriting_identical_bytes_is_not_a_conflict() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);

    let lock = HomeLock::acquire(&home).unwrap();
    let mut transaction = Transaction::begin(&lock).unwrap();
    transaction.document_mut().set_extension("sdks", json!(1));
    put(&path, EMPTY);
    assert!(matches!(
        transaction.commit().unwrap(),
        Commit::Replaced { .. }
    ));
}

#[test]
fn an_unmodified_document_is_not_rewritten_and_keeps_the_users_formatting() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    let original = "{\r\n\t\"schemaVersion\" : 1,\r\n\t\"extensions\" : { \"x\" : [1,2] }\r\n}";
    put(&path, original);
    let modified = fs::metadata(&path).unwrap().modified().unwrap();

    assert_eq!(config::update(&home, |_| {}).unwrap(), Commit::Unchanged);
    assert_eq!(
        config::update(&home, |document| {
            document.set_extension("x", json!([1, 2]));
        })
        .unwrap(),
        Commit::Unchanged
    );
    assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    assert!(snapshots(&home).is_empty());
}

#[test]
fn fingerprints_identify_exact_content() {
    assert_eq!(
        Fingerprint::of(b"abc").to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(Fingerprint::Missing.to_string(), "missing");
    assert_ne!(Fingerprint::of(b"a"), Fingerprint::of(b"a "));

    let (_directory, home) = workspace();
    put(&configuration(&home), EMPTY);
    let lock = HomeLock::acquire(&home).unwrap();
    let transaction = Transaction::begin(&lock).unwrap();
    assert_eq!(
        transaction.original_fingerprint(),
        Fingerprint::of(EMPTY.as_bytes())
    );
}

#[test]
fn malformed_unsupported_and_future_documents_are_rejected_for_editing_and_never_rewritten() {
    let deep = format!(
        "{{\"schemaVersion\":1,\"extensions\":{{\"x\":{}1{}}}}}",
        "[".repeat(200),
        "]".repeat(200)
    );
    let cases: Vec<(&str, Vec<u8>, ErrorKind, &str)> = vec![
        ("empty", b"".to_vec(), ErrorKind::Malformed, "empty"),
        ("blank", b" \r\n\t".to_vec(), ErrorKind::Malformed, "empty"),
        (
            "only a byte order mark",
            b"\xef\xbb\xbf".to_vec(),
            ErrorKind::Malformed,
            "empty",
        ),
        (
            "not JSON",
            b"this is not json".to_vec(),
            ErrorKind::Malformed,
            "not a usable configuration",
        ),
        (
            "trailing text",
            br#"{"schemaVersion":1,"extensions":{}} x"#.to_vec(),
            ErrorKind::Malformed,
            "trailing",
        ),
        (
            "trailing comma",
            br#"{"schemaVersion":1,"extensions":{},}"#.to_vec(),
            ErrorKind::Malformed,
            "trailing comma",
        ),
        (
            "comment",
            b"// note\n{\"schemaVersion\":1,\"extensions\":{}}".to_vec(),
            ErrorKind::Malformed,
            "line 1",
        ),
        (
            "array root",
            b"[]".to_vec(),
            ErrorKind::Malformed,
            "JSON object",
        ),
        (
            "string root",
            b"\"x\"".to_vec(),
            ErrorKind::Malformed,
            "JSON object",
        ),
        (
            "missing version",
            br#"{"extensions":{}}"#.to_vec(),
            ErrorKind::Malformed,
            "schemaVersion",
        ),
        (
            "text version",
            br#"{"schemaVersion":"1","extensions":{}}"#.to_vec(),
            ErrorKind::Malformed,
            "integer",
        ),
        (
            "fractional version",
            br#"{"schemaVersion":1.0,"extensions":{}}"#.to_vec(),
            ErrorKind::Malformed,
            "integer",
        ),
        (
            "null version",
            br#"{"schemaVersion":null,"extensions":{}}"#.to_vec(),
            ErrorKind::Malformed,
            "integer",
        ),
        (
            "missing extensions",
            br#"{"schemaVersion":1}"#.to_vec(),
            ErrorKind::Malformed,
            "extensions",
        ),
        (
            "extensions array",
            br#"{"schemaVersion":1,"extensions":[]}"#.to_vec(),
            ErrorKind::Malformed,
            "extensions",
        ),
        (
            "extensions null",
            br#"{"schemaVersion":1,"extensions":null}"#.to_vec(),
            ErrorKind::Malformed,
            "extensions",
        ),
        (
            "future version",
            br#"{"schemaVersion":2,"extensions":{"sdks":{"keep":"me"}}}"#.to_vec(),
            ErrorKind::UnsupportedVersion,
            "version 2",
        ),
        (
            "future version without an envelope",
            br#"{"schemaVersion":99,"settings":[]}"#.to_vec(),
            ErrorKind::UnsupportedVersion,
            "version 99",
        ),
        (
            "legacy version",
            br#"{"schemaVersion":0,"extensions":{}}"#.to_vec(),
            ErrorKind::UnsupportedVersion,
            "version 0",
        ),
        (
            "negative version",
            br#"{"schemaVersion":-1,"extensions":{}}"#.to_vec(),
            ErrorKind::UnsupportedVersion,
            "version -1",
        ),
        (
            "version beyond 64 bits",
            br#"{"schemaVersion":99999999999999999999,"extensions":{}}"#.to_vec(),
            ErrorKind::UnsupportedVersion,
            "99999999999999999999",
        ),
        (
            "invalid UTF-8",
            b"{\"schemaVersion\":1,\"extensions\":{\"x\":\"\xff\"}}".to_vec(),
            ErrorKind::Malformed,
            "line 1",
        ),
        (
            "lone surrogate",
            br#"{"schemaVersion":1,"extensions":{"x":"\ud800"}}"#.to_vec(),
            ErrorKind::Malformed,
            "line 1",
        ),
        (
            "nesting too deep",
            deep.into_bytes(),
            ErrorKind::Malformed,
            "recursion limit",
        ),
    ];

    for (name, bytes, kind, mention) in cases {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, &bytes);

        {
            let lock = HomeLock::acquire(&home).unwrap();
            let error = Transaction::begin(&lock).unwrap_err();
            assert_eq!(error.kind(), kind, "{name}: {error}");
            let message = error.to_string();
            assert!(message.contains(mention), "{name}: {message}");
            assert!(message.contains("configuration.json"), "{name}: {message}");
        }
        assert_eq!(config::read(&home).unwrap_err().kind(), kind, "{name}");
        assert_eq!(Document::parse(&bytes).unwrap_err().kind(), kind, "{name}");
        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
        assert_eq!(error.kind(), kind, "{name}");

        assert_eq!(fs::read(&path).unwrap(), bytes, "{name}: was rewritten");
        assert!(snapshots(&home).is_empty(), "{name}");
        assert_nothing_staged(&home);
        HomeLock::try_acquire(&home).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn future_schemas_explain_that_a_newer_muxlet_is_needed() {
    let (_directory, home) = workspace();
    put(
        &configuration(&home),
        r#"{"schemaVersion":7,"extensions":{}}"#,
    );
    let error = config::update(&home, |_| {}).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedVersion);
    let message = error.to_string();
    assert!(message.contains("schema version 7"), "{message}");
    assert!(message.contains("only version 1"), "{message}");
    assert!(message.contains("not changed"), "{message}");
}

#[test]
fn duplicate_keys_anywhere_are_rejected_instead_of_silently_losing_data() {
    let cases = [
        (
            "schemaVersion",
            r#"{"schemaVersion":1,"schemaVersion":1,"extensions":{}}"#,
        ),
        (
            "extensions",
            r#"{"schemaVersion":1,"extensions":{},"extensions":{}}"#,
        ),
        (
            "sdks",
            r#"{"schemaVersion":1,"extensions":{"sdks":{},"sdks":{}}}"#,
        ),
        (
            "b",
            r#"{"schemaVersion":1,"extensions":{"x":{"a":{"b":1,"b":2}}}}"#,
        ),
        (
            "k",
            r#"{"schemaVersion":1,"extensions":{"x":[{"k":1,"k":2}]}}"#,
        ),
        (
            "a",
            r#"{"schemaVersion":1,"extensions":{"x":{"a":1,"\u0061":2}}}"#,
        ),
        (
            "note",
            r#"{"schemaVersion":1,"extensions":{},"note":1,"note":2}"#,
        ),
    ];
    for (key, text) in cases {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, text);

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DuplicateKey, "{text}: {error}");
        assert!(
            error.to_string().contains(&format!("\"{key}\"")),
            "{text}: {error}"
        );
        assert_eq!(
            Document::parse(text.as_bytes()).unwrap_err().kind(),
            ErrorKind::DuplicateKey
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert!(snapshots(&home).is_empty());
    }

    // The same names in different objects are fine.
    let allowed =
        r#"{"schemaVersion":1,"extensions":{"a":{"k":1},"b":{"k":2},"c":[{"k":1},{"k":2}]}}"#;
    Document::parse(allowed.as_bytes()).unwrap();
}

#[test]
fn directories_and_special_files_are_unsupported_entries() {
    let (_directory, home) = workspace();
    fs::create_dir_all(configuration(&home)).unwrap();
    let error = config::update(&home, |_| {}).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
    assert!(error.to_string().contains("directory"), "{error}");
    assert!(configuration(&home).is_dir());

    #[cfg(unix)]
    {
        let (_directory, home) = workspace();
        fs::create_dir_all(&home).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(configuration(&home))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if made {
            // Opening a FIFO would block forever, so this also proves it is never opened.
            let error = config::update(&home, |_| {}).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
            assert!(error.to_string().contains("not a regular file"), "{error}");
        }
    }
}

#[test]
fn a_link_to_a_regular_configuration_is_followed_and_left_in_place() {
    let (directory, home) = workspace();
    let dotfiles = directory.path().join("dot files");
    let target = dotfiles.join("muxlet.json");
    put(&target, EMPTY);
    fs::create_dir_all(&home).unwrap();
    if !symlink_file(&target, &configuration(&home)) {
        return;
    }
    let link_text = fs::read_link(configuration(&home)).unwrap();

    let commit = config::update(&home, add_section("sdks", json!({"a": 1}))).unwrap();
    let Commit::Replaced { snapshot } = commit else {
        panic!("expected a replacement, got {commit:?}");
    };

    assert!(
        fs::symlink_metadata(configuration(&home))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(configuration(&home)).unwrap(), link_text);
    let written: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
    assert_eq!(written["extensions"]["sdks"], json!({"a": 1}));
    assert_eq!(fs::read(&snapshot).unwrap(), EMPTY.as_bytes());
    assert_eq!(
        config::read(&home).unwrap().extension("sdks"),
        Some(&json!({"a": 1}))
    );
    assert_eq!(staging_leftovers(&dotfiles), Vec::<String>::new());
    assert_nothing_staged(&home);
}

#[test]
fn links_that_cannot_be_followed_to_a_regular_file_are_unsupported() {
    // A dangling link: nothing may be created through it.
    let (directory, home) = workspace();
    fs::create_dir_all(&home).unwrap();
    let missing = directory.path().join("does not exist.json");
    if !symlink_file(&missing, &configuration(&home)) {
        return;
    }
    let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
    assert!(!missing.exists(), "nothing may be created through a link");

    // A link to a directory.
    let (directory, home) = workspace();
    fs::create_dir_all(&home).unwrap();
    let folder = directory.path().join("folder");
    fs::create_dir_all(&folder).unwrap();
    assert!(symlink_dir(&folder, &configuration(&home)));
    let error = config::update(&home, |_| {}).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
    assert!(error.to_string().contains("directory"), "{error}");

    // A loop.
    let (directory, home) = workspace();
    fs::create_dir_all(&home).unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    assert!(symlink_file(&second, &first));
    assert!(symlink_file(&first, &second));
    assert!(symlink_file(&first, &configuration(&home)));
    let error = config::update(&home, |_| {}).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
}

#[test]
fn a_link_to_an_unusable_document_is_validated_like_the_document_itself() {
    let (directory, home) = workspace();
    fs::create_dir_all(&home).unwrap();
    let target = directory.path().join("future.json");
    let future = r#"{"schemaVersion":5,"extensions":{}}"#;
    put(&target, future);
    if !symlink_file(&target, &configuration(&home)) {
        return;
    }
    let error = config::update(&home, |_| {}).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedVersion);
    assert_eq!(fs::read_to_string(&target).unwrap(), future);
}

#[test]
fn retargeting_a_link_after_reading_is_detected() {
    let (directory, home) = workspace();
    fs::create_dir_all(&home).unwrap();
    let first = directory.path().join("first.json");
    let second = directory.path().join("second.json");
    put(&first, EMPTY);
    put(&second, EMPTY);
    if !symlink_file(&first, &configuration(&home)) {
        return;
    }

    let lock = HomeLock::acquire(&home).unwrap();
    let mut transaction = Transaction::begin(&lock).unwrap();
    transaction.document_mut().set_extension("sdks", json!(1));
    fs::remove_file(configuration(&home)).unwrap();
    assert!(symlink_file(&second, &configuration(&home)));
    let error = transaction.commit().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Changed);
    assert_eq!(fs::read_to_string(&first).unwrap(), EMPTY);
    assert_eq!(fs::read_to_string(&second).unwrap(), EMPTY);
}

#[test]
fn replaced_originals_are_saved_exactly_read_only_and_named_by_time_and_content() {
    let (_directory, home) = workspace();
    let original = "\u{feff}{\r\n\t\"schemaVersion\" : 1 ,\r\n\t\"extensions\" : { \"keep\" : [ 1 , 2 ] }\r\n}\r\n";
    put(&configuration(&home), original);

    let commit = config::update(&home, add_section("sdks", json!(true))).unwrap();
    let Commit::Replaced { snapshot } = commit else {
        panic!("expected a replacement, got {commit:?}");
    };

    // An exact copy, in the journal, with an identifying name.
    assert_eq!(fs::read(&snapshot).unwrap(), original.as_bytes());
    assert_eq!(snapshot.parent().unwrap(), config::journal_directory(&home));
    let name = snapshot.file_name().unwrap().to_str().unwrap();
    let identity = name
        .strip_prefix("configuration-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .unwrap_or_else(|| panic!("unexpected snapshot name {name}"));
    let (stamp, content) = identity.split_once('-').unwrap();
    assert_eq!(stamp.len(), 16, "{stamp}");
    assert!(
        stamp.ends_with('Z') && stamp.as_bytes()[8] == b'T',
        "{stamp}"
    );
    assert!(stamp[..8].bytes().all(|byte| byte.is_ascii_digit()));
    assert!(stamp.starts_with("20"), "{stamp}");
    assert_eq!(
        content,
        &Fingerprint::of(original.as_bytes()).to_string()[..12]
    );
    assert!(fs::metadata(&snapshot).unwrap().permissions().readonly());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    // The replacement is normalised but keeps the byte order mark and the values.
    let rewritten = fs::read(configuration(&home)).unwrap();
    assert!(rewritten.starts_with(b"\xef\xbb\xbf{\n  \"schemaVersion\": 1,"));
    assert!(!rewritten.contains(&b'\r'));
    let document = Document::parse(&rewritten).unwrap();
    assert_eq!(document.extension("keep"), Some(&json!([1, 2])));
    assert_eq!(document.extension("sdks"), Some(&json!(true)));
}

#[test]
fn buffered_commits_match_the_pretty_form_for_large_values_with_or_without_a_bom() {
    let large = json!({"text": "é\n\"\\value".repeat(4_096), "number": 1.50});
    for bom in [false, true] {
        let (_directory, home) = workspace();
        let mut original = if bom {
            b"\xef\xbb\xbf".to_vec()
        } else {
            Vec::new()
        };
        original.extend_from_slice(EMPTY.as_bytes());
        put(&configuration(&home), &original);

        let commit = config::update(&home, add_section("large", large.clone())).unwrap();
        let Commit::Replaced { snapshot } = commit else {
            panic!("expected a replacement, got {commit:?}");
        };
        let document = config::read(&home).unwrap();
        assert_eq!(document.extension("large"), Some(&large));
        let mut expected = if bom {
            b"\xef\xbb\xbf".to_vec()
        } else {
            Vec::new()
        };
        expected.extend_from_slice(&document.to_bytes());
        assert_eq!(fs::read(configuration(&home)).unwrap(), expected);
        assert_eq!(fs::read(snapshot).unwrap(), original);
        assert_nothing_staged(&home);
    }
}

#[test]
fn snapshots_are_never_modified_by_later_writes() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);

    config::update(&home, add_section("sdks", json!(1))).unwrap();
    let first = snapshots(&home);
    assert_eq!(first.len(), 1);
    let kept = fs::read(&first[0]).unwrap();
    let modified = fs::metadata(&first[0]).unwrap().modified().unwrap();

    // Restoring the same original and replacing it again may reuse the copy but
    // must never alter it, and every snapshot stays an exact copy.
    put(&path, EMPTY);
    config::update(&home, add_section("sdks", json!(1))).unwrap();
    let all = snapshots(&home);
    assert!(all.len() == 1 || all.len() == 2, "{all:?}");
    for snapshot in &all {
        assert_eq!(fs::read(snapshot).unwrap(), EMPTY.as_bytes());
    }
    assert_eq!(fs::read(&first[0]).unwrap(), kept);
    assert_eq!(
        fs::metadata(&first[0]).unwrap().modified().unwrap(),
        modified
    );
}

#[test]
fn an_unwritable_journal_prevents_replacement() {
    // The journal path is occupied by a file.
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);
    put(&home.join("journal"), "not a directory");

    let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.to_string().contains("journal"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);
    assert_nothing_staged(&home);
}

#[cfg(unix)]
mod permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Restores a directory's mode so the workspace can be cleaned up.
    struct Mode(PathBuf, u32);

    impl Drop for Mode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
        }
    }

    fn restrict(path: &Path, mode: u32) -> Mode {
        let original = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        Mode(path.to_owned(), original)
    }

    /// Superusers ignore directory modes, so such tests cannot observe a refusal.
    fn modes_are_enforced(directory: &Path) -> bool {
        let probe = directory.join("probe");
        match fs::write(&probe, b"") {
            Ok(()) => {
                fs::remove_file(probe).unwrap();
                false
            }
            Err(_) => true,
        }
    }

    #[test]
    fn existing_permission_bits_are_kept_and_new_files_are_private() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        config::update(&home, add_section("sdks", json!(1))).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let (_directory, fresh) = workspace();
        config::update(&fresh, add_section("sdks", json!(1))).unwrap();
        assert_eq!(
            fs::metadata(configuration(&fresh))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn a_read_only_configuration_is_refused_not_replaced() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
        assert!(error.to_string().contains("read-only"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);
        assert!(snapshots(&home).is_empty());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn an_unwritable_directory_gives_an_actionable_error_and_changes_nothing() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        drop(HomeLock::acquire(&home).unwrap());
        fs::create_dir_all(config::journal_directory(&home)).unwrap();
        let _restore = restrict(&home, 0o555);
        if !modes_are_enforced(&home) {
            return;
        }

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
        let message = error.to_string();
        assert!(message.contains("never elevates"), "{message}");
        assert!(message.contains(home.to_str().unwrap()), "{message}");
        assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);
        assert!(
            snapshots(&home).is_empty(),
            "refusals leave no journal entry"
        );
    }

    #[test]
    fn an_unwritable_journal_gives_an_actionable_error_and_keeps_the_original() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        let journal = config::journal_directory(&home);
        fs::create_dir_all(&journal).unwrap();
        let _restore = restrict(&journal, 0o555);
        if !modes_are_enforced(&journal) {
            return;
        }

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
        assert!(error.to_string().contains("never elevates"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);
        assert_nothing_staged(&home);
    }

    /// Mode 0o300 leaves a directory searchable and writable but not
    /// readable, so everything works except opening it to flush it: a real
    /// `EACCES` from the operating system, after the rename. Superusers can
    /// open it anyway, so the failure cannot be observed for them.
    fn cannot_be_opened(directory: &Path) -> bool {
        fs::File::open(directory).is_err()
    }

    #[test]
    fn a_failed_flush_of_the_home_after_the_rename_says_the_new_content_is_in_place() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        let restore = restrict(&home, 0o300);
        if !cannot_be_opened(&home) {
            return;
        }

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::NotDurable);
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
        assert_eq!(error.path(), path);
        let message = error.to_string();
        assert!(message.contains("was replaced"), "{message}");
        assert!(message.contains("new content is in place"), "{message}");
        assert!(message.contains("may not survive a crash"), "{message}");
        assert!(!message.contains("not replaced"), "{message}");

        // The message is accurate: the new document is the configuration, and
        // the one it replaced is in the journal, named by the message.
        drop(restore);
        assert_eq!(
            config::read(&home).unwrap().extension("sdks"),
            Some(&json!(1))
        );
        let saved = snapshots(&home);
        assert_eq!(saved.len(), 1);
        assert_eq!(fs::read(&saved[0]).unwrap(), EMPTY.as_bytes());
        assert!(message.contains(saved[0].to_str().unwrap()), "{message}");
        assert_nothing_staged(&home);
    }

    #[test]
    fn a_failed_flush_after_creating_the_configuration_says_it_was_created() {
        let (_directory, home) = workspace();
        fs::create_dir_all(&home).unwrap();
        let restore = restrict(&home, 0o300);
        if !cannot_be_opened(&home) {
            return;
        }

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::NotDurable);
        let message = error.to_string();
        assert!(message.contains("was created"), "{message}");
        assert!(message.contains("new content is in place"), "{message}");
        drop(restore);
        assert_eq!(
            config::read(&home).unwrap().extension("sdks"),
            Some(&json!(1))
        );
        assert!(snapshots(&home).is_empty());
        assert_nothing_staged(&home);
    }

    #[test]
    fn a_failed_flush_of_the_journal_stops_the_commit_and_keeps_the_original() {
        let (_directory, home) = workspace();
        let path = configuration(&home);
        put(&path, EMPTY);
        let journal = config::journal_directory(&home);
        fs::create_dir_all(&journal).unwrap();
        let restore = restrict(&journal, 0o300);
        if !cannot_be_opened(&journal) {
            return;
        }

        let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
        let message = error.to_string();
        assert!(
            message.contains("flush the recovery journal directory"),
            "{message}"
        );
        assert!(
            message.contains("the configuration was not replaced"),
            "{message}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);

        // The copy that was written is complete, so nothing is lost either way.
        drop(restore);
        let saved = snapshots(&home);
        assert_eq!(saved.len(), 1);
        assert_eq!(fs::read(&saved[0]).unwrap(), EMPTY.as_bytes());
        assert_nothing_staged(&home);
    }
}

#[test]
fn a_read_only_configuration_is_never_replaced_on_any_platform() {
    let (_directory, home) = workspace();
    let path = configuration(&home);
    put(&path, EMPTY);
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();

    let error = config::update(&home, add_section("sdks", json!(1))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(fs::read_to_string(&path).unwrap(), EMPTY);
    make_writable(&path);
}

#[test]
fn documents_round_trip_through_their_pretty_form() {
    let mut document = Document::new();
    document.set_extension("sdks", json!({"b": 1, "a": [true, null, 1.5, "é"]}));
    document.set_extension("empty", json!({}));
    let bytes = document.to_bytes();
    assert!(bytes.ends_with(b"}\n"));
    assert_eq!(Document::parse(&bytes).unwrap(), document);
    assert_eq!(Document::parse(&bytes).unwrap().to_bytes(), bytes);
    assert_eq!(document.get("schemaVersion"), Some(&json!(1)));
    assert_eq!(
        document.get("extensions"),
        Some(&Value::Object(document.extensions().clone()))
    );
    assert_eq!(document.get("missing"), None);
    assert_eq!(
        document.remove_extension("sdks"),
        Some(json!({"b": 1, "a": [true, null, 1.5, "é"]}))
    );
    assert_eq!(document.remove_extension("sdks"), None);
}
