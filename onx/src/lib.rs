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
pub mod core {

    /// Represents a network flow (5-tuple)
    ///
    /// A flow is identified by source IP, destination IP, source port,
    /// destination port, and protocol.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Flow {
        // Will be implemented in v0.0.2
    }

    pub fn hello_onx() {
        println!("Open Nexus v0.0.1");
        println!("⚠️  Under active development");
        println!();
        println!("This is a placeholder release to reserve the crate name.");
        println!("Full functionality coming in v0.1.0.");
        println!();
        println!("Repository: https://github.com/OpenSynapsis/open-nexus");
    }
}

/// Packet capture module
pub mod capture {

    // Placeholder for future implementation
}

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
