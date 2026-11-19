use serde::{Deserialize, Serialize};

/// Each record to a command of yours, a JSON line on its stdin. Tangent
/// starts the command when it starts and writes to it as records come; at
/// its stop it closes the command's stdin and waits for it to end. What the
/// command prints goes where tangent's own output goes. Records reach it one
/// write at a time, in the order the sink got them: `in_flight_limit` does
/// nothing here.
///
/// A record is delivered once it is written to the command: one the command
/// has read and not yet acted on when it ends is not sent again. A command
/// that ends is started again for the next record.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    /// The program and its arguments, `[python3, notify.py]`: the program
    /// is found on `PATH`, or by its path from the working directory. It is
    /// no shell's line: `[sh, -c, "..."]` for one.
    pub command: Vec<String>,
}
