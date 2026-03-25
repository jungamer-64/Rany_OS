use alloc::collections::{BTreeMap, VecDeque};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_api::abi::driver::AbiRRefRaw;
use kernel_api::error::KapiError;
use kernel_api::ipc::ChannelHandle;

use crate::sync::PoisonLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelRole {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChannelEntry {
    channel_id: u64,
    role: ChannelRole,
    owner: u64,
}

struct ChannelState {
    queue: VecDeque<AbiRRefRaw>,
    sender_count: usize,
    receiver_count: usize,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            sender_count: 0,
            receiver_count: 0,
        }
    }
}

struct ChannelRegistry {
    handles: PoisonLock<BTreeMap<u64, ChannelEntry>>,
    channels: PoisonLock<BTreeMap<u64, ChannelState>>,
    next_id: AtomicU64,
    next_channel_id: AtomicU64,
}

impl ChannelRegistry {
    const fn new() -> Self {
        Self {
            handles: PoisonLock::new(BTreeMap::new()),
            channels: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            next_channel_id: AtomicU64::new(1),
        }
    }

    fn create_channel(&self, owner: u64) -> (u64, u64) {
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel_id, ChannelState::new());
        let sender = self.register_endpoint(ChannelEntry {
            channel_id,
            role: ChannelRole::Sender,
            owner,
        });
        let receiver = self.register_endpoint(ChannelEntry {
            channel_id,
            role: ChannelRole::Receiver,
            owner,
        });
        (sender, receiver)
    }

    fn register_endpoint(&self, entry: ChannelEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        if let Some(channel) = self
            .channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&entry.channel_id)
        {
            match entry.role {
                ChannelRole::Sender => channel.sender_count += 1,
                ChannelRole::Receiver => channel.receiver_count += 1,
            }
        }
        id
    }

    fn entry(&self, id: u64) -> Option<ChannelEntry> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .copied()
    }

    fn entry_for_caller(&self, id: u64, caller: u64) -> Result<ChannelEntry, KapiError> {
        let entry = self.entry(id).ok_or(KapiError::InvalidHandle)?;
        if entry.owner != caller {
            return Err(KapiError::PermissionDenied);
        }
        Ok(entry)
    }

    fn unregister(&self, id: u64) -> Option<ChannelEntry> {
        let entry = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)?;

        let mut drained = VecDeque::new();
        {
            let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(channel) = channels.get_mut(&entry.channel_id) {
                match entry.role {
                    ChannelRole::Sender => {
                        channel.sender_count = channel.sender_count.saturating_sub(1)
                    }
                    ChannelRole::Receiver => {
                        channel.receiver_count = channel.receiver_count.saturating_sub(1);
                        if channel.receiver_count == 0 {
                            core::mem::swap(&mut drained, &mut channel.queue);
                        }
                    }
                }

                if channel.sender_count == 0 && channel.receiver_count == 0 {
                    if let Some(mut removed) = channels.remove(&entry.channel_id) {
                        drained.append(&mut removed.queue);
                    }
                }
            }
        }

        while let Some(raw) = drained.pop_front() {
            drop_abi_rref_raw(raw);
        }

        Some(entry)
    }

    fn send_raw(
        &self,
        handle: ChannelHandle,
        caller: u64,
        raw: AbiRRefRaw,
    ) -> Result<(), KapiError> {
        let entry = self.entry_for_caller(handle.id(), caller)?;
        if entry.role != ChannelRole::Sender {
            drop_abi_rref_raw(raw);
            return Err(KapiError::PermissionDenied);
        }
        if raw.ptr.is_null() {
            drop_abi_rref_raw(raw);
            return Err(KapiError::PermissionDenied);
        }

        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        let Some(channel) = channels.get_mut(&entry.channel_id) else {
            drop_abi_rref_raw(raw);
            return Err(KapiError::InvalidHandle);
        };
        if channel.receiver_count == 0 {
            drop_abi_rref_raw(raw);
            return Err(KapiError::NotFound);
        }
        channel.queue.push_back(raw);
        Ok(())
    }

    fn recv_raw(&self, handle: ChannelHandle, caller: u64) -> Result<AbiRRefRaw, KapiError> {
        let entry = self.entry_for_caller(handle.id(), caller)?;
        if entry.role != ChannelRole::Receiver {
            return Err(KapiError::PermissionDenied);
        }

        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        let Some(channel) = channels.get_mut(&entry.channel_id) else {
            return Err(KapiError::InvalidHandle);
        };
        let Some(raw) = channel.queue.pop_front() else {
            return Err(if channel.sender_count == 0 {
                KapiError::NotFound
            } else {
                KapiError::ResourceExhausted
            });
        };
        Ok(raw)
    }

    fn unregister_owned(&self, id: u64, caller: u64) -> Result<(), KapiError> {
        self.entry_for_caller(id, caller)?;
        self.unregister(id).ok_or(KapiError::InvalidHandle)?;
        Ok(())
    }
}

static CHANNEL_REGISTRY: ChannelRegistry = ChannelRegistry::new();

pub(crate) fn create_channel(owner: u64) -> (u64, u64) {
    CHANNEL_REGISTRY.create_channel(owner)
}

pub(crate) fn unregister_channel_owned(id: u64, caller: u64) -> Result<(), KapiError> {
    CHANNEL_REGISTRY.unregister_owned(id, caller)
}

pub(crate) fn send_raw(
    handle: ChannelHandle,
    caller: u64,
    raw: AbiRRefRaw,
) -> Result<(), KapiError> {
    CHANNEL_REGISTRY.send_raw(handle, caller, raw)
}

pub(crate) fn recv_raw(handle: ChannelHandle, caller: u64) -> Result<AbiRRefRaw, KapiError> {
    CHANNEL_REGISTRY.recv_raw(handle, caller)
}

pub(crate) fn cleanup_owner(owner: u64) -> usize {
    let ids: alloc::vec::Vec<u64> = CHANNEL_REGISTRY
        .handles
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|(id, entry)| (entry.owner == owner).then_some(*id))
        .collect();

    for id in &ids {
        let _ = CHANNEL_REGISTRY.unregister(*id);
    }

    ids.len()
}

pub(crate) fn drop_abi_rref_raw(raw: AbiRRefRaw) {
    let Some(drop_fn) = raw.drop_fn else {
        return;
    };
    let Some(ptr) = NonNull::new(raw.ptr) else {
        return;
    };
    unsafe {
        drop_fn(ptr.as_ptr(), raw.owner, raw.meta, raw.size, raw.align);
    }
}
