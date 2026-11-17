use anyhow::Result;
use std::hash::{DefaultHasher, Hash, Hasher};

use wasmtime::{Config, Engine};

pub fn build() -> Result<Engine> {
    let mut cfg = Config::new();
    // Async support is always on since wasmtime 48; the linker and the
    // calls say `_async` where it matters.
    //
    // Memory is allocated as an instance is made, not from a pool: every
    // worker has an engine, a grouped plugin's workers too, and a pool
    // reserves 4 TiB of address space for each, which three pools of twelve
    // workers do not fit in. A plugin's instances live as long as their
    // worker, so there is nothing for a pool to make faster.
    cfg.wasm_component_model(true)
        .debug_info(false)
        .wasm_backtrace_max_frames(None)
        .generate_address_map(false)
        .native_unwind_info(false)
        .profiler(wasmtime::ProfilingStrategy::None)
        .parallel_compilation(false);

    Ok(Engine::new(&cfg)?)
}

/// What a `.cwasm` made by [`build`]'s engine is compiled for, as a number:
/// wasmtime's version and settings and this machine's CPU features. A
/// `.cwasm` made for another number fails to load here.
pub fn compatibility() -> Result<u64> {
    Ok(number(&build()?))
}

fn number(engine: &Engine) -> u64 {
    let mut h = DefaultHasher::new();
    engine.precompile_compatibility_hash().hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_engine_that_compiles_otherwise_has_another_number() {
        let ours = compatibility().unwrap();
        assert_eq!(ours, compatibility().unwrap(), "the same on every run");
        let mut cfg = Config::new();
        cfg.wasm_component_model(true)
            .cranelift_opt_level(wasmtime::OptLevel::None);
        assert_ne!(ours, number(&Engine::new(&cfg).unwrap()));
    }
}
