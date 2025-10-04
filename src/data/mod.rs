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