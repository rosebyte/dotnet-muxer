//! Detection of `dotnet` wrapper cycles which still allows legitimate nested
//! SDK calls.
//!
//! Forwarding to an opaque wrapper records a hop (this process's ID and start
//! time, and the target) in the child's private `MUXLET_FORWARD_CHAIN`. A later
//! dispatcher keeps only the hops of live processes in its own ancestry, up to
//! the nearest recognised .NET host, and refuses a target already among them.
//! Forwarding straight to a recognised host clears the context.

use std::collections::HashSet;
use std::env;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::resolver;

pub(crate) const CHAIN_ENV: &str = "MUXLET_FORWARD_CHAIN";
const MAX_CHAIN_BYTES: usize = 64 * 1024;
const MAX_HOPS: usize = 64;
const TOO_MANY_HOPS: &str =
    "too many unresolved dotnet wrappers; set DOTNET_ROOT to the genuine installation";

/// Process `pid`, started at `started`, forwarded to `target` (native path bytes).
#[derive(Deserialize, Serialize)]
struct Hop {
    pid: u32,
    started: u64,
    target: Vec<u8>,
}

pub(crate) fn prepare(command: &mut Command, target: &Path) -> Result<()> {
    if resolver::is_known_host(target)? {
        command.env_remove(CHAIN_ENV);
        return Ok(());
    }

    let mut chain = inherited_chain()?;
    let current = Pid::from_u32(std::process::id());
    let mut system = System::new();
    // This process and its live ancestors, as (pid, start time), up to the
    // nearest recognised host: past one, a call is a legitimate nested
    // invocation. With no inherited hops, only this process is needed.
    let mut live = Vec::new();
    let mut visited = HashSet::new();
    let mut next = Some(current);
    while let Some(pid) = next.filter(|pid| visited.insert(*pid)) {
        let Some(process) = refresh(&mut system, pid) else {
            break;
        };
        if pid != current && process.exe().map_or(Ok(false), resolver::is_known_host)? {
            break;
        }
        live.push((pid.as_u32(), process.start_time()));
        next = process.parent().filter(|_| !chain.is_empty());
    }
    let &(_, started) = live
        .first()
        .context("cannot identify this process to prevent recursive dotnet forwarding")?;

    let target_key = target.as_os_str().as_encoded_bytes();
    chain.retain(|hop| live.contains(&(hop.pid, hop.started)));
    if chain.iter().any(|hop| hop.target == target_key) {
        bail!(
            "recursive dotnet forwarding through '{}'; \
             set DOTNET_ROOT to the genuine .NET installation, not a wrapper",
            target.display()
        );
    }
    if chain.len() >= MAX_HOPS {
        bail!(TOO_MANY_HOPS);
    }
    chain.push(Hop {
        pid: current.as_u32(),
        started,
        target: target_key.to_vec(),
    });
    command.env(
        CHAIN_ENV,
        serde_json::to_string(&chain).context("cannot encode Muxlet forwarding context")?,
    );
    Ok(())
}

/// The hops recorded by the dispatchers whose forwarding led to this one.
fn inherited_chain() -> Result<Vec<Hop>> {
    let Some(value) = env::var_os(CHAIN_ENV) else {
        return Ok(Vec::new());
    };
    let text = value
        .to_str()
        .context("invalid internal MUXLET_FORWARD_CHAIN encoding")?;
    if text.len() > MAX_CHAIN_BYTES {
        bail!("internal Muxlet forwarding context is too large");
    }
    let chain: Vec<Hop> =
        serde_json::from_str(text).context("invalid internal Muxlet forwarding context")?;
    if chain.len() > MAX_HOPS {
        bail!(TOO_MANY_HOPS);
    }
    Ok(chain)
}

/// Refreshes the record of process `pid`, executable included, and returns it
/// while the process lives.
fn refresh(system: &mut System, pid: Pid) -> Option<&Process> {
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    system.process(pid)
}
