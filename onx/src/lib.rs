//! Open Nexus (onx) - Flow-based network packet capture and analysis
//!
//! ⚠️ **Early Development**: This crate is under active development.
//! APIs will change frequently until v0.1.0.
//!
//! ## What is Open Nexus?
//!
//! Traditional packet capture tools give you raw packet lists.
//! Open Nexus indexes packets by flows, making filtering and analysis
//! orders of magnitude faster.
//!
//! ## Project Status
//!
//! Currently in initial development (v0.0.x). Basic structure is in place,
//! core features are being implemented.

/// Core flow analysis module
pub mod core;

/// Packet capture module
pub mod capture;

/// Export functionality module
pub mod export {
    // Placeholder for future implementation
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        // Basic smoke test
        assert_eq!(2 + 2, 4);
    }
}
