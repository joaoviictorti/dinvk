// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

//! Structures and types used across the library.

mod types;
mod structs;
mod constant;

pub use types::*;
pub use structs::*;
pub use constant::*;

#[repr(C)]
pub enum EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
}