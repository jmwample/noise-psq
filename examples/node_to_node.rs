
//! Example demonstrating and workshoping the interface for establishing mutually
//! authenticated connections between nodes that know about eachother ahead of time.

struct Node {
    ident_key: (),
    static_key: (),
    node_id: u64,
}

struct NodeDescriptor {
    ident_cert: (),
    public_key: (),
    node_id: u64,
}



fn main() -> Result<(), Box<dyn std::error::Error>> {

    Ok(())
}
