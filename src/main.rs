//! Crux Mesh CLI — distributed knowledge graph tool for LLM agents.

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use crux_mesh::adapters::CruxAdapter;
use crux_mesh::adapters::scanner::{scan_directory, generate_dir, GroupingStrategy};
use crux_mesh::mesh;
use crux_mesh::schema;

fn print_help() {
    eprintln!("crux — distributed knowledge graph mesh for LLM agents");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  crux <command> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  create <name> [--kind <kind>]         Create a new crux");
    eprintln!("  generate <name> <input> [--format f]  Generate crux from a single file");
    eprintln!("    (both refuse to overwrite an existing .crux.json; pass --force to replace it)");
    eprintln!("  scan <path> [--depth n]               Scan a directory and list all files");
    eprintln!("  generate-dir <source> <output> <mesh> Generate cruxes from a directory");
    eprintln!("  load <path>                           Load and display a crux summary");
    eprintln!("  query <path> <filter>                 Query nodes by tag/name/kind");
    eprintln!();
    eprintln!("Mesh commands:");
    eprintln!("  mesh init <name>                      Create a new mesh manifest");
    eprintln!("  mesh join <crux-path>                 Add a crux to the mesh");
    eprintln!("  mesh leave <name-or-id>               Remove a crux from the mesh");
    eprintln!("  mesh status                           Show mesh health and members");
    eprintln!("  mesh query <filter>                   Query nodes across all mesh members");
    eprintln!("  mesh build <name> <crux-dir>          Init mesh and join all cruxes in dir");
    eprintln!("  mesh create-cluster <name>            Create an access-control cluster");
    eprintln!("  mesh assign-cluster <crux> <cluster>  Assign a crux to a cluster");
    eprintln!("  mesh policy [set <key> <value>]       View or edit mesh policy");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --mcp                          Start MCP server (JSON-RPC 2.0 over stdio)");
    eprintln!("  --help                         Show this help message");
    eprintln!("  --version                      Show version");
    eprintln!();
    eprintln!("Crux kinds: codebase, documentation, preferences, organization,");
    eprintln!("            skillset, api, dataset, custom");
    eprintln!("Formats:    auto, markdown, plaintext, manual");
    eprintln!("Strategies: by_kind (default), by_directory, flat");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        process::exit(0);
    }

    match args[1].as_str() {
        "--help" | "-h" => {
            print_help();
        }
        "--version" | "-V" => {
            eprintln!("crux-mesh {}", env!("CARGO_PKG_VERSION"));
        }
        "--mcp" => {
            crux_mesh::mcp::run_mcp_server();
        }
        "create" => cmd_create(&args[2..]),
        "generate" => cmd_generate(&args[2..]),
        "scan" => cmd_scan(&args[2..]),
        "generate-dir" => cmd_generate_dir(&args[2..]),
        "load" => cmd_load(&args[2..]),
        "query" => cmd_query(&args[2..]),
        "mesh" => {
            if args.len() < 3 {
                eprintln!("Usage: crux mesh <init|join|leave|status>");
                process::exit(1);
            }
            if args[2] == "--help" || args[2] == "-h" {
                print_help();
                process::exit(0);
            }
            match args[2].as_str() {
                "init" => cmd_mesh_init(&args[3..]),
                "join" => cmd_mesh_join(&args[3..]),
                "leave" => cmd_mesh_leave(&args[3..]),
                "status" => cmd_mesh_status(&args[3..]),
                "query" => cmd_mesh_query(&args[3..]),
                "build" => cmd_mesh_build(&args[3..]),
                "create-cluster" => cmd_mesh_create_cluster(&args[3..]),
                "assign-cluster" => cmd_mesh_assign_cluster(&args[3..]),
                "policy" => cmd_mesh_policy(&args[3..]),
                other => {
                    eprintln!("Unknown mesh command: {}", other);
                    process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Run 'crux --help' for usage.");
            process::exit(1);
        }
    }
}

// ===========================================================================
// Argument helpers
//
// Every subcommand used to read its positionals straight out of `args[0..]`
// with no check on their shape, and `--help` was only recognized before
// dispatch. The result was that flags landed in positional slots and were used
// as data: `crux create --help` created a crux literally named "--help", and
// `crux mesh init --name m` created a mesh named "--name". Several commands
// also ended their option loop with `_ => i += 1`, so a mistyped flag was
// silently dropped and the command ran with defaults.
// ===========================================================================

/// True if `tok` is flag-shaped rather than a positional value.
///
/// A bare `-` is conventionally stdin, so it is not treated as a flag. No
/// positional in this CLI is ever a negative number, so a leading `-`
/// elsewhere is unambiguous.
fn is_flag(tok: &str) -> bool {
    tok.len() > 1 && tok.starts_with('-')
}

/// True if a help flag appears anywhere in `args`.
///
/// Scanning the whole slice means `crux mesh join --help` works as well as
/// `crux --help`. The cost is that a literal `--help` can't be passed as a
/// value (e.g. as a query string) — an acceptable trade for a tool whose
/// positionals are names and paths.
fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// Outcome of validating a subcommand's positional arguments. Split out from
/// [`require_positionals`] so it can be tested without `process::exit`.
#[derive(Debug, PartialEq)]
enum ArgCheck {
    Ok,
    Help,
    /// Fewer positionals than required; carries how many were supplied.
    Missing(usize),
    /// A flag appeared where a value was expected; carries the flag and index.
    FlagInPositional(String, usize),
}

/// Validate that `args` begins with `required` genuine positional values.
fn check_positionals(args: &[String], required: usize) -> ArgCheck {
    if wants_help(args) {
        return ArgCheck::Help;
    }
    for (i, a) in args.iter().take(required).enumerate() {
        if is_flag(a) {
            return ArgCheck::FlagInPositional(a.clone(), i);
        }
    }
    if args.len() < required {
        return ArgCheck::Missing(args.len());
    }
    ArgCheck::Ok
}

/// Exiting wrapper around [`check_positionals`]. Usage goes to stderr to match
/// the rest of this file; `--help` is a success, a bad invocation is not.
fn require_positionals(args: &[String], required: usize, usage: &str) {
    match check_positionals(args, required) {
        ArgCheck::Ok => {}
        ArgCheck::Help => {
            eprintln!("{}", usage);
            process::exit(0);
        }
        ArgCheck::Missing(got) => {
            eprintln!("Error: expected {} argument(s), got {}.", required, got);
            eprintln!("{}", usage);
            process::exit(1);
        }
        ArgCheck::FlagInPositional(flag, idx) => {
            eprintln!(
                "Error: expected a value at position {}, found option '{}'.",
                idx + 1,
                flag
            );
            eprintln!("{}", usage);
            process::exit(1);
        }
    }
}

/// Read the value following option `opt` at `idx`, or fail with a message that
/// names the option — rather than reporting it as unknown.
fn require_value<'a>(args: &'a [String], idx: usize, opt: &str, usage: &str) -> &'a str {
    match args.get(idx + 1) {
        Some(v) if !is_flag(v) => v,
        _ => {
            eprintln!("Error: option '{}' requires a value.", opt);
            eprintln!("{}", usage);
            process::exit(1);
        }
    }
}

/// Parse a numeric option value, failing loudly rather than falling back to a
/// default. `--depth abc` previously went through `.parse().ok()` and silently
/// became "no limit".
fn parse_usize(val: &str, opt: &str, usage: &str) -> usize {
    match val.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: option '{}' expects a number, got '{}'.", opt, val);
            eprintln!("{}", usage);
            process::exit(1);
        }
    }
}

/// Reject an unrecognized argument instead of silently skipping it.
fn unknown_option(opt: &str, usage: &str) -> ! {
    eprintln!("Error: unrecognized argument '{}'.", opt);
    eprintln!("{}", usage);
    process::exit(1);
}

/// Reject trailing arguments for commands that accept no options.
fn require_no_extra(args: &[String], positionals: usize, usage: &str) {
    if args.len() > positionals {
        unknown_option(&args[positionals], usage);
    }
}

/// Refuse to overwrite an existing crux unless `force`.
///
/// `save_crux_db` is an unconditional write and `create`/`generate` both target
/// the current directory, so a mistyped invocation silently destroyed every
/// node and edge in an existing `.crux.json`. `mesh::init_mesh` has always
/// guarded its manifest this way; this brings crux creation in line.
fn guard_existing_crux(dir: &Path, force: bool) {
    let path = dir.join(".crux.json");
    if path.exists() && !force {
        eprintln!("Error: Crux already exists at {}", path.display());
        eprintln!("Overwriting discards all of its nodes and edges. Pass --force to do it anyway.");
        process::exit(1);
    }
}

// ===========================================================================
// Command implementations
// ===========================================================================

fn cmd_create(args: &[String]) {
    const USAGE: &str =
        "Usage: crux create <name> [--kind <kind>] [--origin <origin>] [--force]";
    require_positionals(args, 1, USAGE);

    let name = &args[0];
    let mut kind_str = "codebase";
    let mut origin = "manual";
    let mut force = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" => {
                kind_str = require_value(args, i, "--kind", USAGE);
                i += 2;
            }
            "--origin" => {
                origin = require_value(args, i, "--origin", USAGE);
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    let kind = schema::CruxKind::from_str(kind_str);
    let db = schema::create_crux_db(name, kind, origin);
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    guard_existing_crux(&cwd, force);

    match schema::save_crux_db(&db, &cwd) {
        Ok(()) => {
            println!("Created crux '{}' ({})", name, kind_str);
            println!("  ID: {}", db.header.crux_id);
            println!("  File: {}", cwd.join(".crux.json").display());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_generate(args: &[String]) {
    const USAGE: &str = "Usage: crux generate <name> <input-file> \
                         [--format auto|markdown|plaintext|manual] [--force]";
    require_positionals(args, 2, USAGE);

    let name = &args[0];
    let input_path = &args[1];
    let mut format = "auto".to_string();
    let mut force = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                format = require_value(args, i, "--format", USAGE).to_string();
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    let input = match std::fs::read_to_string(input_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading input file '{}': {}", input_path, e);
            process::exit(1);
        }
    };

    let config = crux_mesh::adapters::AdapterConfig::new(name, &format);
    let db = match format.as_str() {
        "markdown" => crux_mesh::adapters::markdown::MarkdownAdapter.generate(&input, &config),
        "plaintext" => crux_mesh::adapters::plaintext::PlaintextAdapter.generate(&input, &config),
        "manual" => crux_mesh::adapters::manual::ManualAdapter.generate(&input, &config),
        _ => crux_mesh::adapters::auto::AutoAdapter.generate(&input, &config),
    };
    let db = match db {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error generating crux: {}", e);
            process::exit(1);
        }
    };

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    guard_existing_crux(&cwd, force);
    match schema::save_crux_db(&db, &cwd) {
        Ok(()) => {
            println!("Generated crux '{}' from '{}'", name, input_path);
            println!("  ID: {}", db.header.crux_id);
            println!("  Nodes: {}", db.nodes.len());
            println!("  File: {}", cwd.join(".crux.json").display());
        }
        Err(e) => {
            eprintln!("Error saving crux: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_scan(args: &[String]) {
    const USAGE: &str = "Usage: crux scan <path> [--depth <n>] [--ext <ext1,ext2>]";
    require_positionals(args, 1, USAGE);

    let path = PathBuf::from(&args[0]);
    let mut max_depth: Option<usize> = None;
    let mut extensions: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--depth" => {
                max_depth = Some(parse_usize(
                    require_value(args, i, "--depth", USAGE),
                    "--depth",
                    USAGE,
                ));
                i += 2;
            }
            "--ext" => {
                extensions = require_value(args, i, "--ext", USAGE)
                    .split(',')
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty())
                    .collect();
                i += 2;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    match scan_directory(&path, max_depth, &extensions) {
        Ok(result) => {
            println!("{}", result.summary());
            println!();
            for f in &result.files {
                println!("  [{:>8} B] {:12} {}", f.size_bytes, f.kind.as_str(), f.relative_path);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_generate_dir(args: &[String]) {
    const USAGE: &str = "Usage: crux generate-dir <source-dir> <output-dir> <mesh-name>\n\
                         \x20      [--strategy by_kind|by_directory|flat]\n\
                         \x20      [--device <device-id>] [--classification internal|confidential|...]\n\
                         \x20      [--depth <n>]";
    require_positionals(args, 3, USAGE);

    let source = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let mesh_name = &args[2];

    let mut strategy = GroupingStrategy::ByKind;
    let mut device_id: Option<String> = None;
    let mut classification: Option<String> = None;
    let mut max_depth: Option<usize> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--strategy" => {
                strategy = GroupingStrategy::from_str(require_value(args, i, "--strategy", USAGE));
                i += 2;
            }
            "--device" => {
                device_id = Some(require_value(args, i, "--device", USAGE).to_string());
                i += 2;
            }
            "--classification" => {
                classification =
                    Some(require_value(args, i, "--classification", USAGE).to_string());
                i += 2;
            }
            "--depth" => {
                max_depth = Some(parse_usize(
                    require_value(args, i, "--depth", USAGE),
                    "--depth",
                    USAGE,
                ));
                i += 2;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    match generate_dir(
        &source,
        &output,
        mesh_name,
        strategy,
        device_id.as_deref(),
        classification.as_deref(),
        max_depth,
    ) {
        Ok(result) => {
            println!("{}", result.summary);
            println!();
            println!("Created {} crux(es):", result.cruxes.len());
            for (name, path) in &result.cruxes {
                println!("  {} → {}", name, path.display());
            }
            if !result.skipped.is_empty() {
                println!();
                println!("Skipped (binary/unsupported): {} files", result.skipped.len());
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_query(args: &[String]) {
    const USAGE: &str = "Usage: crux query <path> <filter>";
    require_positionals(args, 2, USAGE);
    require_no_extra(args, 2, USAGE);

    let path = PathBuf::from(&args[0]);
    let filter = &args[1];

    let db = match schema::load_crux_db(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error loading crux: {}", e);
            process::exit(1);
        }
    };

    let filter_lower = filter.to_lowercase();
    let matched: Vec<&schema::CruxNode> = db
        .nodes
        .iter()
        .filter(|n| {
            n.deleted_at.is_none()
                && (n.name.to_lowercase().contains(&filter_lower)
                    || n.kind.to_lowercase().contains(&filter_lower)
                    || n.tags.iter().any(|t| t.to_lowercase().contains(&filter_lower)))
        })
        .collect();

    if matched.is_empty() {
        println!("No nodes matching '{}'.", filter);
        return;
    }

    println!("Found {} node(s) matching '{}':", matched.len(), filter);
    for n in &matched {
        println!("  {} ({}) — {}", n.name, n.kind, n.summary);
        if !n.tags.is_empty() {
            println!("    tags: {}", n.tags.join(", "));
        }
    }
}

fn cmd_load(args: &[String]) {
    const USAGE: &str = "Usage: crux load <path>";
    require_positionals(args, 1, USAGE);
    require_no_extra(args, 1, USAGE);

    let path = PathBuf::from(&args[0]);
    let dir = if path.is_file() {
        path.parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf()
    } else {
        path
    };

    match schema::load_crux_db(&dir) {
        Ok(db) => {
            println!("{}", schema::format_crux_summary(&db, None));
        }
        Err(e) => {
            eprintln!("Error loading crux: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_init(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh init <name>";
    require_positionals(args, 1, USAGE);
    require_no_extra(args, 1, USAGE);

    let name = &args[0];
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match mesh::init_mesh(name, &cwd) {
        Ok(manifest) => {
            println!("Initialized mesh '{}'", name);
            println!("  ID: {}", manifest.mesh_id);
            println!("  File: {}", cwd.join(mesh::MESH_MANIFEST_FILE).display());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_join(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh join <crux-path>";
    require_positionals(args, 1, USAGE);
    require_no_extra(args, 1, USAGE);

    let crux_path = &args[0];
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Find the mesh manifest
    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found. Run 'crux mesh init <name>' first.");
            process::exit(1);
        }
    };

    match mesh::join_mesh(&mesh_dir, crux_path) {
        Ok(manifest) => {
            let member = manifest.members.last().unwrap();
            println!(
                "Joined '{}' ({}) to mesh '{}'",
                member.crux_name,
                member.crux_kind.as_str(),
                manifest.mesh_name
            );
            println!("  Members: {}", manifest.members.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_leave(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh leave <name-or-id>";
    require_positionals(args, 1, USAGE);
    require_no_extra(args, 1, USAGE);

    let identifier = &args[0];
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    match mesh::leave_mesh(&mesh_dir, identifier) {
        Ok(manifest) => {
            println!("Removed '{}' from mesh '{}'", identifier, manifest.mesh_name);
            println!("  Remaining members: {}", manifest.members.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_status(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh status [<path>]";
    // The path is optional, so validate the shape of whatever was supplied.
    require_positionals(args, args.len().min(1), USAGE);
    require_no_extra(args, 1, USAGE);

    let cwd = if !args.is_empty() {
        PathBuf::from(&args[0])
    } else {
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    match mesh::load_mesh(&mesh_dir) {
        Ok(mut manifest) => {
            mesh::check_member_health(&mut manifest, &mesh_dir);
            println!("{}", mesh::mesh_status_text(&manifest));
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_query(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh query <filter> [--limit <n>]";
    require_positionals(args, 1, USAGE);

    let query_str = &args[0];
    let mut limit: Option<usize> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                limit = Some(parse_usize(
                    require_value(args, i, "--limit", USAGE),
                    "--limit",
                    USAGE,
                ));
                i += 2;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    let mut filter = crux_mesh::query::NodeFilter::default();
    filter.query = Some(query_str.clone());
    if let Some(lim) = limit { filter.limit = lim; }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    match mesh::load_mesh(&mesh_dir) {
        Ok(manifest) => {
            let results = mesh::mesh_query(&manifest, &mesh_dir, &filter);
            println!("{}", mesh::format_mesh_query_results(&results, query_str));
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_build(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh build <name> <crux-dir> [--output <dir>]";
    require_positionals(args, 2, USAGE);

    let name = &args[0];
    let crux_dir = PathBuf::from(&args[1]);
    let mut output_dir = crux_dir.clone();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                output_dir = PathBuf::from(require_value(args, i, "--output", USAGE));
                i += 2;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    // Init the mesh
    let manifest = match mesh::init_mesh(name, &output_dir) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error initializing mesh: {}", e);
            process::exit(1);
        }
    };

    println!("Initialized mesh '{}'", name);
    println!("  ID: {}", manifest.mesh_id);

    // Join all crux subdirectories
    let entries = match std::fs::read_dir(&crux_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error reading '{}': {}", crux_dir.display(), e);
            process::exit(1);
        }
    };

    let mut joined = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        if !path.join(".crux.json").exists() { continue; }
        let rel = path.strip_prefix(&output_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());
        match mesh::join_mesh(&output_dir, &rel) {
            Ok(_) => {
                println!("  Joined: {}", rel);
                joined += 1;
            }
            Err(e) => eprintln!("  Warning: could not join '{}': {}", rel, e),
        }
    }

    println!("Done. {} crux(es) joined.", joined);
}

fn cmd_mesh_create_cluster(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh create-cluster <name> \
                         [--classification <level>] [--policy <allow|deny|filtered>]";
    require_positionals(args, 1, USAGE);

    let cluster_name = &args[0];
    let mut classification = "internal".to_string();
    let mut policy = "allow".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--classification" => {
                classification = require_value(args, i, "--classification", USAGE).to_string();
                i += 2;
            }
            "--policy" => {
                policy = require_value(args, i, "--policy", USAGE).to_string();
                i += 2;
            }
            _ => unknown_option(&args[i], USAGE),
        }
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    match mesh::create_cluster(&mesh_dir, cluster_name, &classification, &policy) {
        Ok(()) => {
            println!("Created cluster '{}'", cluster_name);
            println!("  Classification: {}", classification);
            println!("  Cross-cluster policy: {}", policy);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_assign_cluster(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh assign-cluster <crux-name> <cluster-name>";
    require_positionals(args, 2, USAGE);
    require_no_extra(args, 2, USAGE);

    let identifier = &args[0];
    let cluster_name = &args[1];

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    match mesh::assign_cluster(&mesh_dir, identifier, cluster_name) {
        Ok(manifest) => {
            println!("Assigned '{}' to cluster '{}'", identifier, cluster_name);
            println!("  Mesh: {}", manifest.mesh_name);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_mesh_policy(args: &[String]) {
    const USAGE: &str = "Usage: crux mesh policy [set <key> <value>]";
    if wants_help(args) {
        eprintln!("{}", USAGE);
        process::exit(0);
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mesh_dir = match mesh::find_mesh(&cwd) {
        Some(d) => d,
        None => {
            eprintln!("No mesh found.");
            process::exit(1);
        }
    };

    let manifest = match mesh::load_mesh(&mesh_dir) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let policy_db = match mesh::load_policy_crux(&manifest, &mesh_dir) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error loading policy crux: {}", e);
            process::exit(1);
        }
    };

    // "set" subcommand: crux mesh policy set <key> <value>
    if args.first().map(|s| s.as_str()) == Some("set") {
        if args.len() < 3 {
            eprintln!("Usage: crux mesh policy set <key> <value>");
            process::exit(1);
        }
        eprintln!("Policy editing via CLI is not yet implemented. Use crux_add_node via MCP.");
        process::exit(1);
    }

    // Default: display policy
    println!("Mesh: {} ({})", manifest.mesh_name, manifest.mesh_id);
    println!();

    let policy_keys = [
        "default_classification",
        "cross_mesh_policy",
        "multi_mesh_allowed",
        "allowed_external_meshes",
        "require_signatures",
        "org_name",
        "org_domain",
        "allowed_crux_kinds",
        "max_members",
        "require_approval",
        "governance_model",
    ];

    println!("Security Policy:");
    for key in &policy_keys[..5] {
        if let Some(val) = schema::get_policy_property(&policy_db, key) {
            println!("  {}: {}", key, val);
        }
    }
    println!();
    println!("Organizational Policy:");
    for key in &policy_keys[5..] {
        if let Some(val) = schema::get_policy_property(&policy_db, key) {
            println!("  {}: {}", key, val);
        }
    }

    let clusters = mesh::list_clusters(&mesh_dir).unwrap_or_default();
    if !clusters.is_empty() {
        println!();
        println!("Clusters: {}", clusters.join(", "));
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_is_flag() {
        assert!(is_flag("--help"));
        assert!(is_flag("-h"));
        assert!(!is_flag("-"), "a bare dash is stdin, not a flag");
        assert!(!is_flag("name"));
        assert!(!is_flag(""));
        assert!(!is_flag("a-b"));
    }

    #[test]
    fn test_wants_help_anywhere_in_args() {
        assert!(wants_help(&argv(&["--help"])));
        assert!(wants_help(&argv(&["-h"])));
        assert!(wants_help(&argv(&["some/path", "--help"])));
        assert!(!wants_help(&argv(&["some/path"])));
        assert!(!wants_help(&[]));
    }

    /// The bug this whole change exists for: `crux create --help` used to take
    /// "--help" as the crux name and write a file.
    #[test]
    fn test_help_flag_is_not_a_positional() {
        assert_eq!(check_positionals(&argv(&["--help"]), 1), ArgCheck::Help);
        assert_eq!(check_positionals(&argv(&["-h"]), 1), ArgCheck::Help);
    }

    /// `crux mesh init --name mymesh` used to create a mesh named "--name".
    #[test]
    fn test_option_in_positional_slot_is_rejected() {
        assert_eq!(
            check_positionals(&argv(&["--name", "mymesh"]), 1),
            ArgCheck::FlagInPositional("--name".to_string(), 0)
        );
        // Also caught when the flag is the second of several positionals.
        assert_eq!(
            check_positionals(&argv(&["name", "--format"]), 2),
            ArgCheck::FlagInPositional("--format".to_string(), 1)
        );
    }

    #[test]
    fn test_check_positionals_accepts_valid() {
        assert_eq!(check_positionals(&argv(&["name"]), 1), ArgCheck::Ok);
        assert_eq!(check_positionals(&argv(&["a", "b"]), 2), ArgCheck::Ok);
        // Options after the positionals are the option loop's business.
        assert_eq!(
            check_positionals(&argv(&["name", "--kind", "codebase"]), 1),
            ArgCheck::Ok
        );
        // A path that merely contains a dash is still a positional.
        assert_eq!(check_positionals(&argv(&["my-crux/.crux.json"]), 1), ArgCheck::Ok);
        assert_eq!(check_positionals(&[], 0), ArgCheck::Ok);
    }

    #[test]
    fn test_check_positionals_reports_missing() {
        assert_eq!(check_positionals(&[], 1), ArgCheck::Missing(0));
        assert_eq!(check_positionals(&argv(&["only"]), 2), ArgCheck::Missing(1));
    }

    /// Help wins over a malformed invocation — `crux create --help` should
    /// explain itself rather than complain about a missing name.
    #[test]
    fn test_help_takes_precedence_over_missing_args() {
        assert_eq!(check_positionals(&argv(&["--help"]), 3), ArgCheck::Help);
    }
}
