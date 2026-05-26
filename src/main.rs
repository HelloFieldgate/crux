//! Crux Mesh CLI — distributed knowledge graph tool for LLM agents.

use std::env;
use std::path::PathBuf;
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
            eprintln!("crux-mesh 0.1.0");
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
// Command implementations
// ===========================================================================

fn cmd_create(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: crux create <name> [--kind <kind>] [--origin <origin>]");
        process::exit(1);
    }

    let name = &args[0];
    let mut kind_str = "codebase";
    let mut origin = "manual";
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" if i + 1 < args.len() => {
                kind_str = &args[i + 1];
                i += 2;
            }
            "--origin" if i + 1 < args.len() => {
                origin = &args[i + 1];
                i += 2;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
    }

    let kind = schema::CruxKind::from_str(kind_str);
    let db = schema::create_crux_db(name, kind, origin);
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

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
    if args.len() < 2 {
        eprintln!("Usage: crux generate <name> <input-file> [--format auto|markdown|plaintext|manual]");
        process::exit(1);
    }

    let name = &args[0];
    let input_path = &args[1];
    let mut format = "auto".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--format" if i + 1 < args.len() => {
                format = args[i + 1].clone();
                i += 2;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
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
    if args.is_empty() {
        eprintln!("Usage: crux scan <path> [--depth <n>] [--ext <ext1,ext2>]");
        process::exit(1);
    }

    let path = PathBuf::from(&args[0]);
    let mut max_depth: Option<usize> = None;
    let mut extensions: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--depth" if i + 1 < args.len() => {
                max_depth = args[i + 1].parse().ok();
                i += 2;
            }
            "--ext" if i + 1 < args.len() => {
                extensions = args[i + 1].split(',')
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty())
                    .collect();
                i += 2;
            }
            _ => i += 1,
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
    if args.len() < 3 {
        eprintln!("Usage: crux generate-dir <source-dir> <output-dir> <mesh-name>");
        eprintln!("       [--strategy by_kind|by_directory|flat]");
        eprintln!("       [--device <device-id>] [--classification internal|confidential|...]");
        eprintln!("       [--depth <n>]");
        process::exit(1);
    }

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
            "--strategy" if i + 1 < args.len() => {
                strategy = GroupingStrategy::from_str(&args[i + 1]);
                i += 2;
            }
            "--device" if i + 1 < args.len() => {
                device_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--classification" if i + 1 < args.len() => {
                classification = Some(args[i + 1].clone());
                i += 2;
            }
            "--depth" if i + 1 < args.len() => {
                max_depth = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
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
    if args.len() < 2 {
        eprintln!("Usage: crux query <path> <filter>");
        process::exit(1);
    }

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
    if args.is_empty() {
        eprintln!("Usage: crux load <path>");
        process::exit(1);
    }

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
    if args.is_empty() {
        eprintln!("Usage: crux mesh init <name>");
        process::exit(1);
    }

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
    if args.is_empty() {
        eprintln!("Usage: crux mesh join <crux-path>");
        process::exit(1);
    }

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
    if args.is_empty() {
        eprintln!("Usage: crux mesh leave <name-or-id>");
        process::exit(1);
    }

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
    if args.is_empty() {
        eprintln!("Usage: crux mesh query <filter> [--limit <n>]");
        process::exit(1);
    }

    let query_str = &args[0];
    let mut limit: Option<usize> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" if i + 1 < args.len() => {
                limit = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
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
    if args.len() < 2 {
        eprintln!("Usage: crux mesh build <name> <crux-dir> [--output <dir>]");
        process::exit(1);
    }

    let name = &args[0];
    let crux_dir = PathBuf::from(&args[1]);
    let mut output_dir = crux_dir.clone();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" if i + 1 < args.len() => {
                output_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
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
    if args.is_empty() {
        eprintln!("Usage: crux mesh create-cluster <name> [--classification <level>] [--policy <allow|deny|filtered>]");
        process::exit(1);
    }

    let cluster_name = &args[0];
    let mut classification = "internal".to_string();
    let mut policy = "allow".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--classification" if i + 1 < args.len() => {
                classification = args[i + 1].clone();
                i += 2;
            }
            "--policy" if i + 1 < args.len() => {
                policy = args[i + 1].clone();
                i += 2;
            }
            _ => i += 1,
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
    if args.len() < 2 {
        eprintln!("Usage: crux mesh assign-cluster <crux-name> <cluster-name>");
        process::exit(1);
    }

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
