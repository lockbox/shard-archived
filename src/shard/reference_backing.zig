//! Implements Backing implementations for [`VarRefernce`]'s during execution
//! and analysis.
//!
//! Abstracts over [`VarReference`] union to essentially store a "running" tally
//! and use for constant propagation where possible to speed up analysis.
const std = @import("std");
