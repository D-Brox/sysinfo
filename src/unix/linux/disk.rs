// Take a look at the license at the top of the repository in the LICENSE file.

use crate::sys::utils::{get_all_utf8_data, to_cpath};
use crate::{Disk, DiskKind};

use libc::statvfs;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

macro_rules! cast {
    ($x:expr) => {
        u64::from($x)
    };
}

#[derive(Debug, Clone)]
pub struct DiskStat {
    read_ops: u64,
    read_bytes: u64,
    write_ops: u64,
    write_bytes: u64,
}

impl DiskStat {
    pub fn from_line(line: &str, sector_size: u64) -> DiskStat {
        let mut s = line.trim().split_whitespace();

        let reads = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();
        let reads_merged = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();
        let sectors_read = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();
        s.next();
        let writes = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();
        let writes_merged = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();
        let sectors_write = s
            .next()
            .map(|s| u64::from_str_radix(s, 10).unwrap())
            .unwrap();

        DiskStat {
            read_ops: reads + reads_merged,
            read_bytes: sectors_read * sector_size,
            write_ops: writes + writes_merged,
            write_bytes: sectors_write * sector_size,
        }
    }
}

pub(crate) struct DiskInner {
    type_: DiskKind,
    device_name: OsString,
    stat_file: PathBuf,
    file_system: OsString,
    mount_point: PathBuf,
    total_space: u64,
    available_space: u64,
    sector_size: u64,
    is_removable: bool,
    is_read_only: bool,

    old_read_bytes: u64,
    old_write_bytes: u64,
    read_bytes: u64,
    write_bytes: u64,

    old_read_ops: u64,
    old_write_ops: u64,
    read_ops: u64,
    write_ops: u64,
}

impl DiskInner {
    pub(crate) fn kind(&self) -> DiskKind {
        self.type_
    }

    pub(crate) fn name(&self) -> &OsStr {
        &self.device_name
    }

    pub(crate) fn file_system(&self) -> &OsStr {
        &self.file_system
    }

    pub(crate) fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub(crate) fn total_space(&self) -> u64 {
        self.total_space
    }

    pub(crate) fn available_space(&self) -> u64 {
        self.available_space
    }

    pub(crate) fn is_removable(&self) -> bool {
        self.is_removable
    }

    pub(crate) fn is_read_only(&self) -> bool {
        self.is_read_only
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.read_bytes.saturating_sub(self.old_read_bytes)
    }

    pub(crate) fn total_bytes_read(&self) -> u64 {
        self.read_bytes
    }

    pub(crate) fn bytes_write(&self) -> u64 {
        self.write_bytes.saturating_sub(self.old_write_bytes)
    }

    pub(crate) fn total_bytes_write(&self) -> u64 {
        self.write_bytes
    }

    pub(crate) fn read_operations(&self) -> u64 {
        self.read_ops.saturating_sub(self.old_read_ops)
    }

    pub(crate) fn total_read_operations(&self) -> u64 {
        self.read_ops
    }

    pub(crate) fn write_operations(&self) -> u64 {
        self.write_ops.saturating_sub(self.old_write_ops)
    }

    pub(crate) fn total_write_operations(&self) -> u64 {
        self.write_ops
    }

    #[inline]
    pub(crate) fn update_disk_stats(&mut self) {
        let mut line = String::new();
        let _ = BufReader::new(
            fs::File::open(self.stat_file.clone()).expect("stat file doesn't exist"),
        )
        .read_line(&mut line);
        let stat = DiskStat::from_line(&line, self.sector_size);
        self.old_read_bytes = self.read_bytes;
        self.old_write_bytes = self.write_bytes;
        self.old_read_ops = self.read_ops;
        self.old_write_ops = self.write_ops;

        self.read_ops = stat.read_ops;
        self.write_ops = stat.write_ops;

        self.read_bytes = stat.read_bytes;
        self.write_bytes = stat.write_bytes;
    }

    pub(crate) fn refresh(&mut self) -> bool {
        self.update_disk_stats();
        unsafe {
            let mut stat: statvfs = mem::zeroed();
            let mount_point_cpath = to_cpath(&self.mount_point);
            if retry_eintr!(statvfs(mount_point_cpath.as_ptr() as *const _, &mut stat)) == 0 {
                let tmp = cast!(stat.f_bsize).saturating_mul(cast!(stat.f_bavail));
                self.available_space = cast!(tmp);
                true
            } else {
                false
            }
        }
    }
}

impl crate::DisksInner {
    pub(crate) fn new() -> Self {
        Self {
            disks: Vec::with_capacity(2),
        }
    }

    pub(crate) fn refresh_list(&mut self) {
        get_all_list(
            &mut self.disks,
            &get_all_utf8_data("/proc/mounts", 16_385).unwrap_or_default(),
        )
    }

    pub(crate) fn list(&self) -> &[Disk] {
        &self.disks
    }

    pub(crate) fn list_mut(&mut self) -> &mut [Disk] {
        &mut self.disks
    }
}

fn new_disk(
    device_name: &OsStr,
    mount_point: &Path,
    file_system: &OsStr,
    removable_entries: &[PathBuf],
) -> Option<Disk> {
    let mount_point_cpath = to_cpath(mount_point);
    let type_ = find_type_for_device_name(device_name);
    let mut total = 0;
    let mut available = 0;
    let mut is_read_only = false;
    unsafe {
        let mut stat: statvfs = mem::zeroed();
        if retry_eintr!(statvfs(mount_point_cpath.as_ptr() as *const _, &mut stat)) == 0 {
            let bsize = cast!(stat.f_bsize);
            let blocks = cast!(stat.f_blocks);
            let bavail = cast!(stat.f_bavail);
            total = bsize.saturating_mul(blocks);
            available = bsize.saturating_mul(bavail);
            is_read_only = (stat.f_flag & libc::ST_RDONLY) != 0;
        }
        if total == 0 {
            return None;
        }
        let mount_point = mount_point.to_owned();
        let is_removable = removable_entries
            .iter()
            .any(|e| e.as_os_str() == device_name);

        let (stat_file, sector_size) = find_stat_for_device_name(device_name);
        let mut line = String::new();
        let _ = BufReader::new(fs::File::open(stat_file.clone()).expect("stat file doesn't exist"))
            .read_line(&mut line);
        let stats = DiskStat::from_line(&line, sector_size);

        Some(Disk {
            inner: DiskInner {
                type_,
                device_name: device_name.to_owned(),
                stat_file,
                file_system: file_system.to_owned(),
                mount_point,
                total_space: cast!(total),
                available_space: cast!(available),
                sector_size,
                is_removable,
                is_read_only,

                read_bytes: stats.read_bytes,
                old_read_bytes: stats.read_bytes,
                read_ops: stats.read_ops,
                old_read_ops: stats.read_ops,

                write_bytes: stats.write_bytes,
                old_write_bytes: stats.write_bytes,
                write_ops: stats.write_ops,
                old_write_ops: stats.write_ops,
            },
        })
    }
}

fn find_stat_for_device_name(device_name: &OsStr) -> (PathBuf, u64) {
    let device_name_path = device_name.to_str().unwrap_or_default();
    let real_path = fs::canonicalize(device_name).unwrap_or_else(|_| PathBuf::from(device_name));
    let mut real_path = real_path.to_str().unwrap_or_default();
    let mut parent_path = "";
    if device_name_path.starts_with("/dev/mapper/") || device_name_path.starts_with("/dev/root") {
        // Recursively solve, for example /dev/dm-0 or /dev/mmcblk0p1
        if real_path != device_name_path {
            return find_stat_for_device_name(OsStr::new(&real_path));
        }
    } else if device_name_path.starts_with("/dev/sd") || device_name_path.starts_with("/dev/vd") {
        // Turn "sda1" into "sda" or "vda1" into "vda"
        real_path = real_path.trim_start_matches("/dev/");
        parent_path = real_path.trim_end_matches(|c| c >= '0' && c <= '9');
    } else if device_name_path.starts_with("/dev/nvme")
        || device_name_path.starts_with("/dev/mmcblk")
    {
        // Turn "nvme0n1p1" into "nvme0n1" or "mmcblk0p1" into "mmcblk0"
        real_path = real_path.trim_start_matches("/dev/");
        if let Some(idx) = real_path.find('p') {
            parent_path = &real_path[..idx]
        };
    } else {
        // Default case: remove /dev/ and expects the name presents under /sys/block/
        // For example, /dev/dm-0 to dm-0
        real_path = real_path.trim_start_matches("/dev/");
    }
    let mut line = String::new();
    let _ = BufReader::new(
        fs::File::open(
            Path::new("/sys/block/")
                .to_owned()
                .join(if parent_path.is_empty() {
                    real_path
                } else {
                    parent_path
                })
                .join("queue/hw_sector_size"),
        )
        .expect("unable to open file"),
    )
    .read_line(&mut line);
    line = line.trim_end().to_string();
    let sector_size = u64::from_str_radix(&line, 10).unwrap();

    (
        Path::new("/sys/block/")
            .to_owned()
            .join(parent_path)
            .join(real_path)
            .join("stat"),
        sector_size,
    )
}

#[allow(clippy::manual_range_contains)]
fn find_type_for_device_name(device_name: &OsStr) -> DiskKind {
    // The format of devices are as follows:
    //  - device_name is symbolic link in the case of /dev/mapper/
    //     and /dev/root, and the target is corresponding device under
    //     /sys/block/
    //  - In the case of /dev/sd, the format is /dev/sd[a-z][1-9],
    //     corresponding to /sys/block/sd[a-z]
    //  - In the case of /dev/nvme, the format is /dev/nvme[0-9]n[0-9]p[0-9],
    //     corresponding to /sys/block/nvme[0-9]n[0-9]
    //  - In the case of /dev/mmcblk, the format is /dev/mmcblk[0-9]p[0-9],
    //     corresponding to /sys/block/mmcblk[0-9]
    let device_name_path = device_name.to_str().unwrap_or_default();
    let real_path = fs::canonicalize(device_name).unwrap_or_else(|_| PathBuf::from(device_name));
    let mut real_path = real_path.to_str().unwrap_or_default();
    if device_name_path.starts_with("/dev/mapper/") || device_name_path.starts_with("/dev/root") {
        // Recursively solve, for example /dev/dm-0 or /dev/mmcblk0p1
        if real_path != device_name_path {
            return find_type_for_device_name(OsStr::new(&real_path));
        }
    } else if device_name_path.starts_with("/dev/sd") || device_name_path.starts_with("/dev/vd") {
        // Turn "sda1" into "sda" or "vda1" into "vda"
        real_path = real_path.trim_start_matches("/dev/");
        real_path = real_path.trim_end_matches(|c| c >= '0' && c <= '9');
    } else if device_name_path.starts_with("/dev/nvme")
        || device_name_path.starts_with("/dev/mmcblk")
    {
        // Turn "nvme0n1p1" into "nvme0n1" or "mmcblk0p1" into "mmcblk0"
        real_path = match real_path.find('p') {
            Some(idx) => &real_path["/dev/".len()..idx],
            None => &real_path["/dev/".len()..],
        };
    } else {
        // Default case: remove /dev/ and expects the name presents under /sys/block/
        // For example, /dev/dm-0 to dm-0
        real_path = real_path.trim_start_matches("/dev/");
    }

    let trimmed: &OsStr = OsStrExt::from_bytes(real_path.as_bytes());

    let path = Path::new("/sys/block/")
        .to_owned()
        .join(trimmed)
        .join("queue/rotational");
    // Normally, this file only contains '0' or '1' but just in case, we get 8 bytes...
    match get_all_utf8_data(path, 8)
        .unwrap_or_default()
        .trim()
        .parse()
        .ok()
    {
        // The disk is marked as rotational so it's a HDD.
        Some(1) => DiskKind::HDD,
        // The disk is marked as non-rotational so it's very likely a SSD.
        Some(0) => DiskKind::SSD,
        // Normally it shouldn't happen but welcome to the wonderful world of IT! :D
        Some(x) => DiskKind::Unknown(x),
        // The information isn't available...
        None => DiskKind::Unknown(-1),
    }
}

fn get_all_list(container: &mut Vec<Disk>, content: &str) {
    container.clear();
    // The goal of this array is to list all removable devices (the ones whose name starts with
    // "usb-").
    let removable_entries = match fs::read_dir("/dev/disk/by-id/") {
        Ok(r) => r
            .filter_map(|res| Some(res.ok()?.path()))
            .filter_map(|e| {
                if e.file_name()
                    .and_then(|x| Some(x.to_str()?.starts_with("usb-")))
                    .unwrap_or_default()
                {
                    e.canonicalize().ok()
                } else {
                    None
                }
            })
            .collect::<Vec<PathBuf>>(),
        _ => Vec::new(),
    };

    for disk in content
        .lines()
        .map(|line| {
            let line = line.trim_start();
            // mounts format
            // http://man7.org/linux/man-pages/man5/fstab.5.html
            // fs_spec<tab>fs_file<tab>fs_vfstype<tab>other fields
            let mut fields = line.split_whitespace();
            let fs_spec = fields.next().unwrap_or("");
            let fs_file = fields
                .next()
                .unwrap_or("")
                .replace("\\134", "\\")
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n");
            let fs_vfstype = fields.next().unwrap_or("");
            (fs_spec, fs_file, fs_vfstype)
        })
        .filter(|(fs_spec, fs_file, fs_vfstype)| {
            // Check if fs_vfstype is one of our 'ignored' file systems.
            let filtered = match *fs_vfstype {
                "rootfs" | // https://www.kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt
                "sysfs" | // pseudo file system for kernel objects
                "proc" |  // another pseudo file system
                "devtmpfs" |
                "cgroup" |
                "cgroup2" |
                "pstore" | // https://www.kernel.org/doc/Documentation/ABI/testing/pstore
                "squashfs" | // squashfs is a compressed read-only file system (for snaps)
                "rpc_pipefs" | // The pipefs pseudo file system service
                "iso9660" // optical media
                => true,
                "tmpfs" => !cfg!(feature = "linux-tmpfs"),
                // calling statvfs on a mounted CIFS or NFS may hang, when they are mounted with option: hard
                "cifs" | "nfs" | "nfs4" => !cfg!(feature = "linux-netdevs"),
                _ => false,
            };

            !(filtered ||
               fs_file.starts_with("/sys") || // check if fs_file is an 'ignored' mount point
               fs_file.starts_with("/proc") ||
               (fs_file.starts_with("/run") && !fs_file.starts_with("/run/media")) ||
               fs_spec.starts_with("sunrpc"))
        })
        .filter_map(|(fs_spec, fs_file, fs_vfstype)| {
            new_disk(
                fs_spec.as_ref(),
                Path::new(&fs_file),
                fs_vfstype.as_ref(),
                &removable_entries,
            )
        })
    {
        container.push(disk);
    }
}

// #[test]
// fn check_all_list() {
//     let disks = get_all_disks_inner(
//         r#"tmpfs /proc tmpfs rw,seclabel,relatime 0 0
// proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
// systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=29,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=17771 0 0
// tmpfs /sys tmpfs rw,seclabel,relatime 0 0
// sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
// securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
// cgroup2 /sys/fs/cgroup cgroup2 rw,seclabel,nosuid,nodev,noexec,relatime,nsdelegate 0 0
// pstore /sys/fs/pstore pstore rw,seclabel,nosuid,nodev,noexec,relatime 0 0
// none /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
// configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0
// selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
// debugfs /sys/kernel/debug debugfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
// tmpfs /dev/shm tmpfs rw,seclabel,relatime 0 0
// devpts /dev/pts devpts rw,seclabel,relatime,gid=5,mode=620,ptmxmode=666 0 0
// tmpfs /sys/fs/selinux tmpfs rw,seclabel,relatime 0 0
// /dev/vda2 /proc/filesystems xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 0
// "#,
//     );
//     assert_eq!(disks.len(), 1);
//     assert_eq!(
//         disks[0],
//         Disk {
//             type_: DiskType::Unknown(-1),
//             name: OsString::from("devpts"),
//             file_system: vec![100, 101, 118, 112, 116, 115],
//             mount_point: PathBuf::from("/dev/pts"),
//             total_space: 0,
//             available_space: 0,
//         }
//     );
// }
