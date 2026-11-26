// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::wire::{
    ExecvePayload, FileOpKind, FileOpPayload, HealthPayload, IpcOpKind, IpcSecurityPayload,
    MAX_ARGV_PREVIEW_LEN, MAX_COMM_LEN, MAX_DETAIL_LEN, MAX_EXEC_PAYLOAD_LEN,
    MAX_HEALTH_PAYLOAD_LEN, MAX_NET_PAYLOAD_LEN, MAX_PATH_LEN, NetOpKind, NetOpPayload,
    RING_EVENT_HEADER_LEN, RING_EVENT_MAGIC, RING_EVENT_VERSION, RingEventHeader, RingEventKind,
    RingEventRecord, RingEventVerdict, RingTaskIds, RingbufChannel, WireDecodeError,
};
use crate::wire_bytes::{
    copy_bounded, get_u8, get_u16, get_u32, get_u64, put_u8, put_u16, put_u32, put_u64,
    read_segment, write_segment,
};

impl RingEventHeader {
    pub const fn new(
        kind: RingEventKind,
        payload_len: u16,
        verdict: RingEventVerdict,
        seq: u64,
        timestamp_ns: u64,
        task: RingTaskIds,
    ) -> Self {
        Self {
            magic: RING_EVENT_MAGIC,
            version: RING_EVENT_VERSION,
            kind,
            payload_len,
            verdict,
            channel: kind.channel(),
            flags: 0,
            seq,
            timestamp_ns,
            tgid_pid: ((task.tgid as u64) << 32) | (task.pid as u64),
            uid_gid: ((task.uid as u64) << 32) | (task.gid as u64),
        }
    }

    pub const fn tgid(&self) -> u32 {
        (self.tgid_pid >> 32) as u32
    }

    pub const fn pid(&self) -> u32 {
        self.tgid_pid as u32
    }

    pub const fn uid(&self) -> u32 {
        (self.uid_gid >> 32) as u32
    }

    pub const fn gid(&self) -> u32 {
        self.uid_gid as u32
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let head = out
            .get_mut(..RING_EVENT_HEADER_LEN)
            .ok_or(WireDecodeError::BufferTooShort)?;
        if let Some(slot) = head.get_mut(0..4) {
            slot.copy_from_slice(&self.magic);
        }
        put_u16(head, 4, self.version)?;
        put_u16(head, 6, self.kind as u16)?;
        put_u16(head, 8, self.payload_len)?;
        put_u8(head, 10, self.verdict as u8)?;
        put_u8(head, 11, self.channel as u8)?;
        put_u32(head, 12, self.flags)?;
        put_u64(head, 16, self.seq)?;
        put_u64(head, 24, self.timestamp_ns)?;
        put_u64(head, 32, self.tgid_pid)?;
        put_u64(head, 40, self.uid_gid)?;
        Ok(RING_EVENT_HEADER_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        let head = bytes
            .get(..RING_EVENT_HEADER_LEN)
            .ok_or(WireDecodeError::BufferTooShort)?;
        let magic = head.get(0..4).ok_or(WireDecodeError::BufferTooShort)?;
        if magic != RING_EVENT_MAGIC {
            return Err(WireDecodeError::InvalidMagic);
        }
        let version = get_u16(head, 4)?;
        if version != RING_EVENT_VERSION {
            return Err(WireDecodeError::UnsupportedVersion);
        }
        let kind = RingEventKind::from_u16(get_u16(head, 6)?)?;
        let payload_len = get_u16(head, 8)?;
        if usize::from(payload_len) > MAX_EXEC_PAYLOAD_LEN {
            return Err(WireDecodeError::PayloadTooLarge);
        }
        let verdict = RingEventVerdict::from_u8(get_u8(head, 10)?)?;
        let channel = RingbufChannel::from_u8(get_u8(head, 11)?)?;
        if channel != kind.channel() {
            return Err(WireDecodeError::ChannelMismatch);
        }
        Ok(Self {
            magic: RING_EVENT_MAGIC,
            version,
            kind,
            payload_len,
            verdict,
            channel,
            flags: get_u32(head, 12)?,
            seq: get_u64(head, 16)?,
            timestamp_ns: get_u64(head, 24)?,
            tgid_pid: get_u64(head, 32)?,
            uid_gid: get_u64(head, 40)?,
        })
    }
}

impl ExecvePayload {
    pub fn from_slices(
        ppid: u32,
        cgroup_id: u64,
        comm: &[u8],
        filename: &[u8],
        argv_preview: &[u8],
    ) -> (Self, bool) {
        let mut out = Self {
            ppid,
            mnt_ns_inum: 0,
            pid_ns_inum: 0,
            net_ns_inum: 0,
            user_ns_inum: 0,
            cgroup_id,
            comm_len: 0,
            filename_len: 0,
            argv_len: 0,
            comm: [0; MAX_COMM_LEN],
            filename: [0; MAX_PATH_LEN],
            argv_preview: [0; MAX_ARGV_PREVIEW_LEN],
        };
        let (c_len, c_trunc) = copy_bounded(&mut out.comm, comm);
        let (f_len, f_trunc) = copy_bounded(&mut out.filename, filename);
        let (a_len, a_trunc) = copy_bounded(&mut out.argv_preview, argv_preview);
        out.comm_len = u8::try_from(c_len).unwrap_or(0);
        out.filename_len = u16::try_from(f_len).unwrap_or(0);
        out.argv_len = u16::try_from(a_len).unwrap_or(0);
        (out, c_trunc || f_trunc || a_trunc)
    }

    pub fn comm_bytes(&self) -> &[u8] {
        self.comm
            .get(..usize::from(self.comm_len).min(MAX_COMM_LEN))
            .unwrap_or(&[])
    }

    pub fn filename_bytes(&self) -> &[u8] {
        self.filename
            .get(..usize::from(self.filename_len).min(MAX_PATH_LEN))
            .unwrap_or(&[])
    }

    pub fn argv_bytes(&self) -> &[u8] {
        self.argv_preview
            .get(..usize::from(self.argv_len).min(MAX_ARGV_PREVIEW_LEN))
            .unwrap_or(&[])
    }

    pub fn encoded_len(&self) -> Result<usize, WireDecodeError> {
        let c = usize::from(self.comm_len);
        let f = usize::from(self.filename_len);
        let a = usize::from(self.argv_len);
        if c > MAX_COMM_LEN || f > MAX_PATH_LEN || a > MAX_ARGV_PREVIEW_LEN {
            return Err(WireDecodeError::BoundsExceeded);
        }
        33usize
            .checked_add(c)
            .and_then(|n| n.checked_add(f))
            .and_then(|n| n.checked_add(a))
            .ok_or(WireDecodeError::PayloadTooLarge)
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let total = self.encoded_len()?;
        let dst = out
            .get_mut(..total)
            .ok_or(WireDecodeError::BufferTooShort)?;
        put_u32(dst, 0, self.ppid)?;
        put_u32(dst, 4, self.mnt_ns_inum)?;
        put_u32(dst, 8, self.pid_ns_inum)?;
        put_u32(dst, 12, self.net_ns_inum)?;
        put_u32(dst, 16, self.user_ns_inum)?;
        put_u64(dst, 20, self.cgroup_id)?;
        put_u8(dst, 28, self.comm_len)?;
        put_u16(dst, 29, self.filename_len)?;
        put_u16(dst, 31, self.argv_len)?;
        let c1 = write_segment(dst, 33, self.comm_bytes())?;
        let c2 = write_segment(dst, c1, self.filename_bytes())?;
        let _end = write_segment(dst, c2, self.argv_bytes())?;
        Ok(total)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < 33 {
            return Err(WireDecodeError::BufferTooShort);
        }
        let comm_len = get_u8(bytes, 28)?;
        let filename_len = get_u16(bytes, 29)?;
        let argv_len = get_u16(bytes, 31)?;
        if usize::from(comm_len) > MAX_COMM_LEN
            || usize::from(filename_len) > MAX_PATH_LEN
            || usize::from(argv_len) > MAX_ARGV_PREVIEW_LEN
        {
            return Err(WireDecodeError::BoundsExceeded);
        }
        let mut out = Self {
            ppid: get_u32(bytes, 0)?,
            mnt_ns_inum: get_u32(bytes, 4)?,
            pid_ns_inum: get_u32(bytes, 8)?,
            net_ns_inum: get_u32(bytes, 12)?,
            user_ns_inum: get_u32(bytes, 16)?,
            cgroup_id: get_u64(bytes, 20)?,
            comm_len,
            filename_len,
            argv_len,
            comm: [0; MAX_COMM_LEN],
            filename: [0; MAX_PATH_LEN],
            argv_preview: [0; MAX_ARGV_PREVIEW_LEN],
        };
        let c1 = read_segment(bytes, 33, usize::from(comm_len), &mut out.comm)?;
        let c2 = read_segment(bytes, c1, usize::from(filename_len), &mut out.filename)?;
        let end = read_segment(bytes, c2, usize::from(argv_len), &mut out.argv_preview)?;
        if end != bytes.len() {
            return Err(WireDecodeError::LengthMismatch);
        }
        Ok(out)
    }
}

impl FileOpPayload {
    pub fn from_paths(
        op: FileOpKind,
        flags: u32,
        mode: u32,
        cgroup_id: u64,
        path: &[u8],
        target_path: &[u8],
    ) -> (Self, bool) {
        let mut out = Self {
            op,
            flags,
            mode,
            cgroup_id,
            dev: 0,
            ino: 0,
            path_len: 0,
            target_path_len: 0,
            path: [0; MAX_PATH_LEN],
            target_path: [0; MAX_PATH_LEN],
        };
        let (p_len, p_trunc) = copy_bounded(&mut out.path, path);
        let (t_len, t_trunc) = copy_bounded(&mut out.target_path, target_path);
        out.path_len = u16::try_from(p_len).unwrap_or(0);
        out.target_path_len = u16::try_from(t_len).unwrap_or(0);
        (out, p_trunc || t_trunc)
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let p = usize::from(self.path_len);
        let t = usize::from(self.target_path_len);
        if p > MAX_PATH_LEN || t > MAX_PATH_LEN {
            return Err(WireDecodeError::BoundsExceeded);
        }
        let total = 37usize
            .checked_add(p)
            .and_then(|n| n.checked_add(t))
            .ok_or(WireDecodeError::PayloadTooLarge)?;
        let dst = out
            .get_mut(..total)
            .ok_or(WireDecodeError::BufferTooShort)?;
        put_u8(dst, 0, self.op as u8)?;
        put_u32(dst, 1, self.flags)?;
        put_u32(dst, 5, self.mode)?;
        put_u64(dst, 9, self.cgroup_id)?;
        put_u64(dst, 17, self.dev)?;
        put_u64(dst, 25, self.ino)?;
        put_u16(dst, 33, self.path_len)?;
        put_u16(dst, 35, self.target_path_len)?;
        let c1 = write_segment(dst, 37, self.path.get(..p).unwrap_or(&[]))?;
        let _end = write_segment(dst, c1, self.target_path.get(..t).unwrap_or(&[]))?;
        Ok(total)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < 37 {
            return Err(WireDecodeError::BufferTooShort);
        }
        let op = FileOpKind::from_u8(get_u8(bytes, 0)?)?;
        let path_len = get_u16(bytes, 33)?;
        let target_path_len = get_u16(bytes, 35)?;
        if usize::from(path_len) > MAX_PATH_LEN || usize::from(target_path_len) > MAX_PATH_LEN {
            return Err(WireDecodeError::BoundsExceeded);
        }
        let mut out = Self {
            op,
            flags: get_u32(bytes, 1)?,
            mode: get_u32(bytes, 5)?,
            cgroup_id: get_u64(bytes, 9)?,
            dev: get_u64(bytes, 17)?,
            ino: get_u64(bytes, 25)?,
            path_len,
            target_path_len,
            path: [0; MAX_PATH_LEN],
            target_path: [0; MAX_PATH_LEN],
        };
        let c1 = read_segment(bytes, 37, usize::from(path_len), &mut out.path)?;
        let end = read_segment(
            bytes,
            c1,
            usize::from(target_path_len),
            &mut out.target_path,
        )?;
        if end != bytes.len() {
            return Err(WireDecodeError::LengthMismatch);
        }
        Ok(out)
    }
}

impl NetOpPayload {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let dst = out
            .get_mut(..MAX_NET_PAYLOAD_LEN)
            .ok_or(WireDecodeError::BufferTooShort)?;
        put_u8(dst, 0, self.op as u8)?;
        put_u16(dst, 1, self.family)?;
        put_u16(dst, 3, self.protocol)?;
        put_u16(dst, 5, self.port)?;
        put_u64(dst, 7, self.cgroup_id)?;
        put_u32(dst, 15, self.egress_ifindex)?;
        let _end = write_segment(dst, 19, &self.addr)?;
        Ok(MAX_NET_PAYLOAD_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < MAX_NET_PAYLOAD_LEN {
            return Err(WireDecodeError::BufferTooShort);
        }
        if bytes.len() != MAX_NET_PAYLOAD_LEN {
            return Err(WireDecodeError::LengthMismatch);
        }
        let family = get_u16(bytes, 1)?;
        if family != 2 && family != 10 {
            return Err(WireDecodeError::InvalidAddressFamily);
        }
        let mut addr = [0u8; 16];
        let _end = read_segment(bytes, 19, 16, &mut addr)?;
        Ok(Self {
            op: NetOpKind::from_u8(get_u8(bytes, 0)?)?,
            family,
            protocol: get_u16(bytes, 3)?,
            port: get_u16(bytes, 5)?,
            cgroup_id: get_u64(bytes, 7)?,
            egress_ifindex: get_u32(bytes, 15)?,
            addr,
        })
    }
}

impl IpcSecurityPayload {
    pub fn from_detail(
        op: IpcOpKind,
        target_pid: u32,
        prev_uid: u32,
        next_uid: u32,
        cgroup_id: u64,
        capability_bits: u64,
        detail: &[u8],
    ) -> (Self, bool) {
        let mut out = Self {
            op,
            target_pid,
            prev_uid,
            next_uid,
            cgroup_id,
            capability_bits,
            detail_len: 0,
            detail: [0; MAX_DETAIL_LEN],
        };
        let (len, truncated) = copy_bounded(&mut out.detail, detail);
        out.detail_len = u16::try_from(len).unwrap_or(0);
        (out, truncated)
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let detail_len = usize::from(self.detail_len);
        if detail_len > MAX_DETAIL_LEN {
            return Err(WireDecodeError::BoundsExceeded);
        }
        let total = 31usize
            .checked_add(detail_len)
            .ok_or(WireDecodeError::PayloadTooLarge)?;
        let dst = out
            .get_mut(..total)
            .ok_or(WireDecodeError::BufferTooShort)?;
        put_u8(dst, 0, self.op as u8)?;
        put_u32(dst, 1, self.target_pid)?;
        put_u32(dst, 5, self.prev_uid)?;
        put_u32(dst, 9, self.next_uid)?;
        put_u64(dst, 13, self.cgroup_id)?;
        put_u64(dst, 21, self.capability_bits)?;
        put_u16(dst, 29, self.detail_len)?;
        let _end = write_segment(dst, 31, self.detail.get(..detail_len).unwrap_or(&[]))?;
        Ok(total)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < 31 {
            return Err(WireDecodeError::BufferTooShort);
        }
        let detail_len = get_u16(bytes, 29)?;
        if usize::from(detail_len) > MAX_DETAIL_LEN {
            return Err(WireDecodeError::BoundsExceeded);
        }
        let mut out = Self {
            op: IpcOpKind::from_u8(get_u8(bytes, 0)?)?,
            target_pid: get_u32(bytes, 1)?,
            prev_uid: get_u32(bytes, 5)?,
            next_uid: get_u32(bytes, 9)?,
            cgroup_id: get_u64(bytes, 13)?,
            capability_bits: get_u64(bytes, 21)?,
            detail_len,
            detail: [0; MAX_DETAIL_LEN],
        };
        let end = read_segment(bytes, 31, usize::from(detail_len), &mut out.detail)?;
        if end != bytes.len() {
            return Err(WireDecodeError::LengthMismatch);
        }
        Ok(out)
    }
}

impl HealthPayload {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireDecodeError> {
        let dst = out
            .get_mut(..MAX_HEALTH_PAYLOAD_LEN)
            .ok_or(WireDecodeError::BufferTooShort)?;
        put_u8(dst, 0, self.channel as u8)?;
        put_u16(dst, 1, self.ring_utilization_permille)?;
        put_u32(dst, 3, self.active_hooks_mask)?;
        put_u64(dst, 7, self.dropped_events)?;
        Ok(MAX_HEALTH_PAYLOAD_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        match bytes.len().cmp(&MAX_HEALTH_PAYLOAD_LEN) {
            core::cmp::Ordering::Less => return Err(WireDecodeError::BufferTooShort),
            core::cmp::Ordering::Greater => return Err(WireDecodeError::LengthMismatch),
            core::cmp::Ordering::Equal => {}
        }
        Ok(Self {
            channel: RingbufChannel::from_u8(get_u8(bytes, 0)?)?,
            ring_utilization_permille: get_u16(bytes, 1)?,
            active_hooks_mask: get_u32(bytes, 3)?,
            dropped_events: get_u64(bytes, 7)?,
        })
    }
}

pub fn encode_event_frame(
    header: &RingEventHeader,
    record: &RingEventRecord,
    out: &mut [u8],
) -> Result<usize, WireDecodeError> {
    let payload_buf = out
        .get_mut(RING_EVENT_HEADER_LEN..)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let payload_len = match record {
        RingEventRecord::Execve(p) => p.encode(payload_buf)?,
        RingEventRecord::FileOp(p) => p.encode(payload_buf)?,
        RingEventRecord::NetOp(p) => p.encode(payload_buf)?,
        RingEventRecord::Ipc(p) => p.encode(payload_buf)?,
        RingEventRecord::ProcExit => 0,
        RingEventRecord::Health(p) => p.encode(payload_buf)?,
    };
    let mut final_header = *header;
    final_header.channel = final_header.kind.channel();
    final_header.payload_len =
        u16::try_from(payload_len).map_err(|_| WireDecodeError::PayloadTooLarge)?;
    let _ = final_header.encode(out)?;
    RING_EVENT_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WireDecodeError::PayloadTooLarge)
}

pub fn decode_event_frame(
    bytes: &[u8],
) -> Result<(RingEventHeader, RingEventRecord), WireDecodeError> {
    let header = RingEventHeader::decode(bytes)?;
    let end = RING_EVENT_HEADER_LEN
        .checked_add(usize::from(header.payload_len))
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    match bytes.len().cmp(&end) {
        core::cmp::Ordering::Less => return Err(WireDecodeError::BufferTooShort),
        core::cmp::Ordering::Greater => return Err(WireDecodeError::LengthMismatch),
        core::cmp::Ordering::Equal => {}
    }
    let payload = bytes
        .get(RING_EVENT_HEADER_LEN..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let record = match header.kind {
        RingEventKind::Execve => RingEventRecord::Execve(ExecvePayload::decode(payload)?),
        RingEventKind::FileOpen | RingEventKind::FileRename | RingEventKind::FileUnlink => {
            RingEventRecord::FileOp(FileOpPayload::decode(payload)?)
        }
        RingEventKind::NetConnect | RingEventKind::NetBind => {
            RingEventRecord::NetOp(NetOpPayload::decode(payload)?)
        }
        RingEventKind::TaskPtrace
        | RingEventKind::CredSetuid
        | RingEventKind::ModuleOrBpfTamper => {
            RingEventRecord::Ipc(IpcSecurityPayload::decode(payload)?)
        }
        RingEventKind::ProcExit => {
            if header.payload_len != 0 {
                return Err(WireDecodeError::LengthMismatch);
            }
            RingEventRecord::ProcExit
        }
        RingEventKind::HealthLost => RingEventRecord::Health(HealthPayload::decode(payload)?),
    };
    Ok((header, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::MAX_RING_FRAME_LEN;

    #[test]
    fn roundtrips_execve_file_net_ipc_and_health_frames() {
        let mut buf = [0u8; MAX_RING_FRAME_LEN];
        let task = RingTaskIds {
            tgid: 202,
            pid: 202,
            uid: 1000,
            gid: 1000,
        };
        let (exec_payload, truncated) =
            ExecvePayload::from_slices(101, 42, b"claude", b"/usr/bin/git", b"git status");
        assert!(!truncated);
        let exec_hdr = RingEventHeader::new(
            RingEventKind::Execve,
            0,
            RingEventVerdict::Allowed,
            1,
            999,
            task,
        );
        let len = encode_event_frame(&exec_hdr, &RingEventRecord::Execve(exec_payload), &mut buf)
            .unwrap_or(0);
        assert!(len > RING_EVENT_HEADER_LEN);
        let (decoded_hdr, decoded_rec) = decode_event_frame(buf.get(..len).unwrap_or(&[]))
            .unwrap_or((exec_hdr, RingEventRecord::ProcExit));
        assert_eq!(decoded_hdr.tgid(), 202);
        assert_eq!(decoded_hdr.channel, RingbufChannel::Exec);
        assert_eq!(decoded_rec, RingEventRecord::Execve(exec_payload));

        let (file_payload, _) = FileOpPayload::from_paths(
            FileOpKind::Rename,
            2,
            0o600,
            42,
            b"/workspace/a.txt",
            b"/workspace/b.txt",
        );
        let file_hdr = RingEventHeader::new(
            RingEventKind::FileRename,
            0,
            RingEventVerdict::Denied,
            2,
            1001,
            RingTaskIds { pid: 203, ..task },
        );
        let flen = encode_event_frame(&file_hdr, &RingEventRecord::FileOp(file_payload), &mut buf)
            .unwrap_or(0);
        assert!(matches!(
            decode_event_frame(buf.get(..flen).unwrap_or(&[])),
            Ok((_, RingEventRecord::FileOp(p))) if p == file_payload
        ));

        let net_payload = NetOpPayload {
            op: NetOpKind::Connect,
            family: 2,
            protocol: 6,
            port: 443,
            cgroup_id: 42,
            egress_ifindex: 3,
            addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let net_hdr = RingEventHeader::new(
            RingEventKind::NetConnect,
            0,
            RingEventVerdict::Observed,
            3,
            1002,
            RingTaskIds { pid: 204, ..task },
        );
        let nlen = encode_event_frame(&net_hdr, &RingEventRecord::NetOp(net_payload), &mut buf)
            .unwrap_or(0);
        assert!(matches!(
            decode_event_frame(buf.get(..nlen).unwrap_or(&[])),
            Ok((_, RingEventRecord::NetOp(p))) if p == net_payload
        ));

        let (ipc_payload, _) = IpcSecurityPayload::from_detail(
            IpcOpKind::Ptrace,
            777,
            1000,
            0,
            42,
            1 << 19,
            b"ptrace_attach",
        );
        let ipc_hdr = RingEventHeader::new(
            RingEventKind::TaskPtrace,
            0,
            RingEventVerdict::Denied,
            4,
            1003,
            RingTaskIds { pid: 205, ..task },
        );
        let ilen =
            encode_event_frame(&ipc_hdr, &RingEventRecord::Ipc(ipc_payload), &mut buf).unwrap_or(0);
        assert!(matches!(
            decode_event_frame(buf.get(..ilen).unwrap_or(&[])),
            Ok((_, RingEventRecord::Ipc(p))) if p == ipc_payload
        ));

        let health = HealthPayload {
            channel: RingbufChannel::File,
            ring_utilization_permille: 750,
            active_hooks_mask: 0x3FF,
            dropped_events: 12,
        };
        let health_hdr = RingEventHeader::new(
            RingEventKind::HealthLost,
            0,
            RingEventVerdict::Observed,
            5,
            1004,
            RingTaskIds {
                tgid: 0,
                pid: 0,
                uid: 0,
                gid: 0,
            },
        );
        let hlen = encode_event_frame(&health_hdr, &RingEventRecord::Health(health), &mut buf)
            .unwrap_or(0);
        assert!(matches!(
            decode_event_frame(buf.get(..hlen).unwrap_or(&[])),
            Ok((_, RingEventRecord::Health(p))) if p == health
        ));
    }

    #[test]
    fn rejects_invalid_magic_short_buffers_and_out_of_bounds_lengths() {
        let short = [0u8; 8];
        assert_eq!(
            decode_event_frame(&short),
            Err(WireDecodeError::BufferTooShort)
        );

        let mut bad_magic = [0u8; RING_EVENT_HEADER_LEN];
        bad_magic[0..4].copy_from_slice(b"NOPE");
        assert_eq!(
            RingEventHeader::decode(&bad_magic),
            Err(WireDecodeError::InvalidMagic)
        );

        let mut buf = [0u8; MAX_RING_FRAME_LEN];
        let (exec_payload, _) = ExecvePayload::from_slices(1, 1, b"sh", b"/bin/sh", b"-c id");
        let hdr = RingEventHeader::new(
            RingEventKind::Execve,
            0,
            RingEventVerdict::Allowed,
            1,
            1,
            RingTaskIds {
                tgid: 10,
                pid: 10,
                uid: 0,
                gid: 0,
            },
        );
        let len =
            encode_event_frame(&hdr, &RingEventRecord::Execve(exec_payload), &mut buf).unwrap_or(0);
        assert!(len > RING_EVENT_HEADER_LEN);
        buf[RING_EVENT_HEADER_LEN + 29] = 0xFF;
        buf[RING_EVENT_HEADER_LEN + 30] = 0x09;
        assert_eq!(
            decode_event_frame(buf.get(..len).unwrap_or(&[])),
            Err(WireDecodeError::BoundsExceeded)
        );
    }

    #[test]
    fn rejects_channel_mismatch_trailing_bytes_procexit_payload_and_invalid_net_family() {
        let mut buf = [0u8; MAX_RING_FRAME_LEN + 8];
        let task = RingTaskIds {
            tgid: 1,
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let exit_hdr = RingEventHeader::new(
            RingEventKind::ProcExit,
            0,
            RingEventVerdict::Observed,
            1,
            1,
            task,
        );
        let elen = encode_event_frame(&exit_hdr, &RingEventRecord::ProcExit, &mut buf).unwrap_or(0);
        assert_eq!(elen, RING_EVENT_HEADER_LEN);
        assert!(matches!(
            decode_event_frame(buf.get(..elen).unwrap_or(&[])),
            Ok((_, RingEventRecord::ProcExit))
        ));

        buf[elen] = 0xAA;
        assert_eq!(
            decode_event_frame(buf.get(..elen + 1).unwrap_or(&[])),
            Err(WireDecodeError::LengthMismatch)
        );

        let mut bad_exit = buf;
        bad_exit[8] = 1;
        bad_exit[9] = 0;
        assert_eq!(
            decode_event_frame(bad_exit.get(..RING_EVENT_HEADER_LEN + 1).unwrap_or(&[])),
            Err(WireDecodeError::LengthMismatch)
        );

        let mut bad_chan = buf;
        bad_chan[11] = RingbufChannel::Net as u8;
        assert_eq!(
            decode_event_frame(bad_chan.get(..elen).unwrap_or(&[])),
            Err(WireDecodeError::ChannelMismatch)
        );

        let bad_net = NetOpPayload {
            op: NetOpKind::Connect,
            family: 99,
            protocol: 6,
            port: 443,
            cgroup_id: 1,
            egress_ifindex: 0,
            addr: [0; 16],
        };
        let net_hdr = RingEventHeader::new(
            RingEventKind::NetConnect,
            0,
            RingEventVerdict::Observed,
            2,
            2,
            task,
        );
        let nlen =
            encode_event_frame(&net_hdr, &RingEventRecord::NetOp(bad_net), &mut buf).unwrap_or(0);
        assert_eq!(
            decode_event_frame(buf.get(..nlen).unwrap_or(&[])),
            Err(WireDecodeError::InvalidAddressFamily)
        );
    }
}
