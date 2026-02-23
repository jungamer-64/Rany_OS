use super::*;

#[cfg_attr(test, test_case)]
pub fn test_pool_id() {
    let id = PoolId::new(42);
    assert_eq!(id.as_u32(), 42);
}

#[cfg_attr(test, test_case)]
pub fn test_sg_list() {
    let mut sg = SgList::new();
    assert!(sg.is_empty());
    assert_eq!(sg.total_len(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_packet_chain() {
    let chain = PacketChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
}
