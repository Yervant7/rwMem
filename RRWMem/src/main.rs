use std::cmp::max;
use bitvec::{order::Lsb0, vec::BitVec};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::{ptr, str};
use std::ffi::CString;
use std::str::Split;
use std::time::Instant;
use byteorder::{NativeEndian, ReadBytesExt};
use nix::request_code_readwrite;
use nix::fcntl;
use nix::sys::stat;
use nix::errno::{Errno};
use rayon::prelude::*;
use capstone::prelude::*;
use keystone_engine::{Arch, Mode, Keystone};

mod errors;

type Result<T> = std::result::Result<T, errors::Error>;

const RWMEM_MAGIC: u8 = 100;
const IOCTL_GET_PROCESS_MAPS_COUNT: u8 = 0;
const IOCTL_GET_PROCESS_MAPS_LIST: u8 = 1;
const IOCTL_CHECK_PROCESS_ADDR_PHY: u8 = 2;
const IOCTL_MEM_SEARCH_INT: u8 = 3;
const IOCTL_MEM_SEARCH_FLOAT: u8 = 4;
const IOCTL_MEM_SEARCH_LONG: u8 = 5;
const IOCTL_MEM_SEARCH_DOUBLE: u8 = 6;
const IOCTL_GET_MODULE_RANGE: u8 = 7;

#[repr(C)]
#[derive(Debug)]
struct SearchParamsInt {
    pid: libc::pid_t,
    is_force_read: bool,
    value_to_compare: libc::c_int,
    addresses: [u64; 200],
    num_addresses: libc::size_t,
    matching_addresses: [u64; 200],
    num_matching_addresses: libc::size_t,
}

#[repr(C)]
#[derive(Debug)]
struct SearchParamsFloat {
    pid: libc::pid_t,
    is_force_read: bool,
    value_to_compare: libc::c_float,
    addresses: [u64; 200],
    num_addresses: libc::size_t,
    matching_addresses: [u64; 200],
    num_matching_addresses: libc::size_t,
}

#[repr(C)]
#[derive(Debug)]
struct SearchParamsLong {
    pid: libc::pid_t,
    is_force_read: bool,
    value_to_compare: libc::c_long,
    addresses: [u64; 200],
    num_addresses: libc::size_t,
    matching_addresses: [u64; 200],
    num_matching_addresses: libc::size_t,
}

#[repr(C)]
#[derive(Debug)]
struct SearchParamsDouble {
    pid: libc::pid_t,
    is_force_read: bool,
    value_to_compare: libc::c_double,
    addresses: [u64; 200],
    num_addresses: libc::size_t,
    matching_addresses: [u64; 200],
    num_matching_addresses: libc::size_t,
}

#[repr(C)]
#[derive(Debug)]
struct ModuleRange {
    pid: libc::pid_t,
    name: [libc::c_char; 256],
    address_base: u64,
    address_end: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MapsEntry {
    pub start: u64,
    pub end: u64,
    pub read_permission: bool,
    pub write_permission: bool,
    pub execute_permission: bool,
    pub shared: bool,
    pub name: String,
}

pub const DEFAULT_DRIVER_PATH: &str = "/dev/rwMem";

#[repr(transparent)]
pub struct Device {
    fd: RawFd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryRegion {
    CAlloc,
    CBss,
    CData,
    CHeap,
    JavaHeap,
    AAnonymous,
    CodeSystem,
    Stack,
    Ashmem,
}

impl MemoryRegion {
    fn from_str(s: &str) -> Option<MemoryRegion> {
        match s {
            "C_ALLOC" => Some(MemoryRegion::CAlloc),
            "C_BSS" => Some(MemoryRegion::CBss),
            "C_DATA" => Some(MemoryRegion::CData),
            "C_HEAP" => Some(MemoryRegion::CHeap),
            "JAVA_HEAP" => Some(MemoryRegion::JavaHeap),
            "A_ANONYMOUS" => Some(MemoryRegion::AAnonymous),
            "CODE_SYSTEM" => Some(MemoryRegion::CodeSystem),
            "STACK" => Some(MemoryRegion::Stack),
            "ASHMEM" => Some(MemoryRegion::Ashmem),
            _ => None,
        }
    }

    fn matches(&self, entry: &MapsEntry) -> bool {
        match self {
            MemoryRegion::CAlloc => entry.name.contains("[anon:libc_malloc]"),
            MemoryRegion::CBss => entry.name.contains("[anon:.bss]"),
            MemoryRegion::CData => entry.name.contains("/data/app/"),
            MemoryRegion::CHeap => entry.name.contains("[heap]"),
            MemoryRegion::JavaHeap => entry.name.contains("/dev/ashmem"),
            MemoryRegion::AAnonymous => entry.name.is_empty(),
            MemoryRegion::CodeSystem => entry.name.contains("/system"),
            MemoryRegion::Stack => entry.name.contains("[stack]"),
            MemoryRegion::Ashmem => entry.name.contains("/dev/ashmem/dalvik"),
        }
    }
}


impl Device {
    /// Create a new device. The default path is `DEFAULT_DRIVER_PATH`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let fd = fcntl::open(
            path.as_ref(),
            fcntl::OFlag::O_RDWR,
            stat::Mode::empty(),
        )?;
        Ok(Self { fd })
    }

    /// read the memory of a process.
    pub fn read_mem(&self, pid: i32, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 17 {
            let new_buf = &mut [0u8; 17];
            new_buf[0..8].copy_from_slice(&(pid as i64).to_ne_bytes());
            new_buf[8..16].copy_from_slice(&addr.to_ne_bytes());
            new_buf[16] = 1;
            let real_read = nix::errno::Errno::result(unsafe {
                libc::read(
                    self.fd,
                    new_buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            })?;
            if real_read != buf.len() as isize {
                return Err(errors::Error::ReadFailed(buf.len(), real_read as usize));
            }
            buf.copy_from_slice(&new_buf[..buf.len()]);
        } else {
            buf[0..8].copy_from_slice(&(pid as i64).to_ne_bytes());
            buf[8..16].copy_from_slice(&addr.to_ne_bytes());
            buf[16] = 1;
            buf[17] = 0;
            let real_read = nix::errno::Errno::result(unsafe {
                libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            })?;
            if real_read != buf.len() as isize {
                return Err(errors::Error::ReadFailed(buf.len(), real_read as usize));
            }
        }
        Ok(())
    }

    /// write the memory of a process.
    pub fn write_mem(&self, pid: i32, addr: u64, buf: &[u8]) -> Result<()> {
        let mut new_buf = vec![0u8; 17 + buf.len()];
        new_buf[0..8].copy_from_slice(&(pid as i64).to_ne_bytes());
        new_buf[8..16].copy_from_slice(&addr.to_ne_bytes());
        new_buf[16] = 1;
        new_buf[17..].copy_from_slice(buf);

        let real_write = Errno::result(unsafe {
            libc::write(self.fd, new_buf.as_ptr() as *const libc::c_void, new_buf.len())
        })?;
        if real_write != new_buf.len() as isize {
            return Err(errors::Error::WriteFailed(new_buf.len(), real_write as usize));
        }
        Ok(())
    }

    pub fn search_memory_int(&self, pid: i32, addresses: &[u64], value_to_compare: i32) -> Result<Vec<u64>> {
        let num_addresses = addresses.len();
        let mut params = SearchParamsInt {
            pid,
            is_force_read: true,
            value_to_compare: 0,
            addresses: [0; 200],
            num_addresses,
            matching_addresses: [0; 200],
            num_matching_addresses: 0,
        };

        for (i, &address) in addresses.iter().enumerate() {
            params.addresses[i] = address;
        }

        params.value_to_compare = value_to_compare as libc::c_int;

        let ret = unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(RWMEM_MAGIC, IOCTL_MEM_SEARCH_INT, std::mem::size_of::<SearchParamsInt>()),
                &mut params as *mut _ as *mut libc::c_void,
            )
        };

        if ret < 0 {
            return Err(errors::Error::IoctlFailed);
        }

        let matching_addresses = params.matching_addresses[..params.num_matching_addresses].to_vec();

        Ok(matching_addresses)
    }

    pub fn search_memory_float(&self, pid: i32, addresses: &[u64], value_to_compare: f32) -> Result<Vec<u64>> {
        let num_addresses = addresses.len();
        let mut params = SearchParamsFloat {
            pid,
            is_force_read: true,
            value_to_compare: 0.0,
            addresses: [0; 200],
            num_addresses,
            matching_addresses: [0; 200],
            num_matching_addresses: 0,
        };

        for (i, &address) in addresses.iter().enumerate() {
            params.addresses[i] = address;
        }

        params.value_to_compare = value_to_compare as libc::c_float;

        let ret = unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(RWMEM_MAGIC, IOCTL_MEM_SEARCH_FLOAT, std::mem::size_of::<SearchParamsFloat>()),
                &mut params as *mut _ as *mut libc::c_void,
            )
        };

        if ret < 0 {
            return Err(errors::Error::IoctlFailed);
        }

        let matching_addresses = params.matching_addresses[..params.num_matching_addresses].to_vec();

        Ok(matching_addresses)
    }

    pub fn search_memory_long(&self, pid: i32, addresses: &[u64], value_to_compare: i64) -> Result<Vec<u64>> {
        let num_addresses = addresses.len();
        let mut params = SearchParamsLong {
            pid,
            is_force_read: true,
            value_to_compare: 0,
            addresses: [0; 200],
            num_addresses,
            matching_addresses: [0; 200],
            num_matching_addresses: 0,
        };

        for (i, &address) in addresses.iter().enumerate() {
            params.addresses[i] = address;
        }

        params.value_to_compare = value_to_compare as libc::c_long;


        let ret = unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(RWMEM_MAGIC, IOCTL_MEM_SEARCH_LONG, std::mem::size_of::<SearchParamsLong>()),
                &mut params as *mut _ as *mut libc::c_void,
            )
        };

        if ret < 0 {
            return Err(errors::Error::IoctlFailed);
        }

        let matching_addresses = params.matching_addresses[..params.num_matching_addresses].to_vec();

        Ok(matching_addresses)
    }

    pub fn search_memory_double(&self, pid: i32, addresses: &[u64], value_to_compare: f64) -> Result<Vec<u64>> {
        let num_addresses = addresses.len();
        let mut params = SearchParamsDouble {
            pid,
            is_force_read: true,
            value_to_compare: 0.0,
            addresses: [0; 200],
            num_addresses,
            matching_addresses: [0; 200],
            num_matching_addresses: 0,
        };

        for (i, &address) in addresses.iter().enumerate() {
            params.addresses[i] = address;
        }

        params.value_to_compare = value_to_compare as libc::c_double;


        let ret = unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(RWMEM_MAGIC, IOCTL_MEM_SEARCH_DOUBLE, std::mem::size_of::<SearchParamsDouble>()),
                &mut params as *mut _ as *mut libc::c_void,
            )
        };

        if ret < 0 {
            return Err(errors::Error::IoctlFailed);
        }

        let matching_addresses = params.matching_addresses[..params.num_matching_addresses].to_vec();

        Ok(matching_addresses)
    }

    fn search_value_int(&self, pid: i32, value: i32, regions: Vec<MemoryRegion>, name: String) -> Result<Vec<u64>> {
        if name == "" {
            let maps = self.get_mem_map(pid, false)?
                .into_iter()
                .filter(|map| regions.iter().any(|region| region.matches(map)))
                .collect::<Vec<_>>();

            let results: Vec<u64> = regions.par_iter()
                .flat_map(|&region| {
                    maps.par_iter()
                        .filter(|map| region.matches(map) && map.read_permission)
                        .flat_map(|map| {
                            let mut local_addresses = Vec::new();
                            let mut addr = map.start;

                            while addr + std::mem::size_of::<i32>() as u64 <= map.end {
                                let mut addrs_to_read = Vec::new();
                                let mut current_addr = addr;

                                while current_addr + std::mem::size_of::<i32>() as u64 <= map.end && addrs_to_read.len() < 200 {
                                    addrs_to_read.push(current_addr);
                                    current_addr += std::mem::size_of::<i32>() as u64;
                                }

                                match self.search_memory_int(pid, &addrs_to_read, value) {
                                    Ok(matching_addresses) => {
                                        local_addresses.extend(matching_addresses);
                                    },
                                    Err(_e) => {}
                                }
                                addr = current_addr;
                            }

                            local_addresses.into_par_iter()
                        })
                        .collect::<Vec<u64>>()
                })
                .collect();

            Ok(results)
        } else {
            let result = unsafe { self.get_module_mem_range(pid, name) };
            match result {
                Ok(range_addresses) => {
                    if range_addresses.is_empty() {
                        return Err(errors::Error::InvalidInput("Or failed to get range address".to_string()));
                    }

                    let start = range_addresses[0];
                    let end = range_addresses[1];
                    let mut local_addresses = Vec::new();
                    let mut addr = start;
                    while addr + std::mem::size_of::<i32>() as u64 <= end {
                        let mut addrs_to_read = Vec::new();
                        let mut current_addr = addr;

                        while current_addr + std::mem::size_of::<i32>() as u64 <= end && addrs_to_read.len() < 200 {
                            addrs_to_read.push(current_addr);
                            current_addr += std::mem::size_of::<i32>() as u64;
                        }

                        match self.search_memory_int(pid, &addrs_to_read, value) {
                            Ok(matching_addresses) => {
                                local_addresses.extend(matching_addresses);
                            },
                            Err(_e) => {}
                        }
                        addr = current_addr;
                    }

                    Ok(local_addresses)
                },
                Err(e) => Err(e),
            }
        }
    }

    fn search_value_float(&self, pid: i32, value: f32, regions: Vec<MemoryRegion>, name: String) -> Result<Vec<u64>> {
        if name == "" {
            let maps = self.get_mem_map(pid, false)?
                .into_iter()
                .filter(|map| regions.iter().any(|region| region.matches(map)))
                .collect::<Vec<_>>();

            let results: Vec<u64> = regions.par_iter()
                .flat_map(|&region| {
                    maps.par_iter()
                        .filter(|map| region.matches(map) && map.read_permission)
                        .flat_map(|map| {
                            let mut local_addresses = Vec::new();
                            let mut addr = map.start;

                            while addr + std::mem::size_of::<f32>() as u64 <= map.end {
                                let mut addrs_to_read = Vec::new();
                                let mut current_addr = addr;

                                while current_addr + std::mem::size_of::<f32>() as u64 <= map.end && addrs_to_read.len() < 200 {
                                    addrs_to_read.push(current_addr);
                                    current_addr += std::mem::size_of::<f32>() as u64;
                                }

                                match self.search_memory_float(pid, &addrs_to_read, value) {
                                    Ok(matching_addresses) => {
                                        local_addresses.extend(matching_addresses);
                                    },
                                    Err(_e) => {}
                                }
                                addr = current_addr;
                            }

                            local_addresses.into_par_iter()
                        })
                        .collect::<Vec<u64>>()
                })
                .collect();

            Ok(results)
        } else {
            let result = unsafe { self.get_module_mem_range(pid, name) };
            match result {
                Ok(range_addresses) => {
                    if range_addresses.is_empty() {
                        return Err(errors::Error::InvalidInput("Or failed to get range address".to_string()));
                    }

                    let start = range_addresses[0];
                    let end = range_addresses[1];
                    let mut local_addresses = Vec::new();
                    let mut addr = start;
                    while addr + std::mem::size_of::<f32>() as u64 <= end {
                        let mut addrs_to_read = Vec::new();
                        let mut current_addr = addr;

                        while current_addr + std::mem::size_of::<f32>() as u64 <= end && addrs_to_read.len() < 200 {
                            addrs_to_read.push(current_addr);
                            current_addr += std::mem::size_of::<f32>() as u64;
                        }

                        match self.search_memory_float(pid, &addrs_to_read, value) {
                            Ok(matching_addresses) => {
                                local_addresses.extend(matching_addresses);
                            },
                            Err(_e) => {}
                        }
                        addr = current_addr;
                    }

                    Ok(local_addresses)
                },
                Err(e) => Err(e),
            }
        }
    }

    fn search_value_long(&self, pid: i32, value: i64, regions: Vec<MemoryRegion>, name: String) -> Result<Vec<u64>> {
        if name == "" {
            let maps = self.get_mem_map(pid, false)?
                .into_iter()
                .filter(|map| regions.iter().any(|region| region.matches(map)))
                .collect::<Vec<_>>();

            let results: Vec<u64> = regions.par_iter()
                .flat_map(|&region| {
                    maps.par_iter()
                        .filter(|map| region.matches(map) && map.read_permission)
                        .flat_map(|map| {
                            let mut local_addresses = Vec::new();
                            let mut addr = map.start;

                            while addr + std::mem::size_of::<i64>() as u64 <= map.end {
                                let mut addrs_to_read = Vec::new();
                                let mut current_addr = addr;

                                while current_addr + std::mem::size_of::<i64>() as u64 <= map.end && addrs_to_read.len() < 200 {
                                    addrs_to_read.push(current_addr);
                                    current_addr += std::mem::size_of::<i64>() as u64;
                                }

                                match self.search_memory_long(pid, &addrs_to_read, value) {
                                    Ok(matching_addresses) => {
                                        local_addresses.extend(matching_addresses);
                                    },
                                    Err(_e) => {}
                                }
                                addr = current_addr;
                            }

                            local_addresses.into_par_iter()
                        })
                        .collect::<Vec<u64>>()
                })
                .collect();

            Ok(results)
        } else {
            let result = unsafe { self.get_module_mem_range(pid, name) };
            match result {
                Ok(range_addresses) => {
                    if range_addresses.is_empty() {
                        return Err(errors::Error::InvalidInput("Or failed to get range address".to_string()));
                    }

                    let start = range_addresses[0];
                    let end = range_addresses[1];
                    let mut local_addresses = Vec::new();
                    let mut addr = start;
                    while addr + std::mem::size_of::<i64>() as u64 <= end {
                        let mut addrs_to_read = Vec::new();
                        let mut current_addr = addr;

                        while current_addr + std::mem::size_of::<i64>() as u64 <= end && addrs_to_read.len() < 200 {
                            addrs_to_read.push(current_addr);
                            current_addr += std::mem::size_of::<i64>() as u64;
                        }

                        match self.search_memory_long(pid, &addrs_to_read, value) {
                            Ok(matching_addresses) => {
                                local_addresses.extend(matching_addresses);
                            },
                            Err(_e) => {}
                        }
                        addr = current_addr;
                    }

                    Ok(local_addresses)
                },
                Err(e) => Err(e),
            }
        }
    }

    fn search_value_double(&self, pid: i32, value: f64, regions: Vec<MemoryRegion>, name: String) -> Result<Vec<u64>> {
        if name == "" {
            let maps = self.get_mem_map(pid, false)?
                .into_iter()
                .filter(|map| regions.iter().any(|region| region.matches(map)))
                .collect::<Vec<_>>();

            let results: Vec<u64> = regions.par_iter()
                .flat_map(|&region| {
                    maps.par_iter()
                        .filter(|map| region.matches(map) && map.read_permission)
                        .flat_map(|map| {
                            let mut local_addresses = Vec::new();
                            let mut addr = map.start;

                            while addr + std::mem::size_of::<f64>() as u64 <= map.end {
                                let mut addrs_to_read = Vec::new();
                                let mut current_addr = addr;

                                while current_addr + std::mem::size_of::<f64>() as u64 <= map.end && addrs_to_read.len() < 200 {
                                    addrs_to_read.push(current_addr);
                                    current_addr += std::mem::size_of::<f64>() as u64;
                                }

                                match self.search_memory_double(pid, &addrs_to_read, value) {
                                    Ok(matching_addresses) => {
                                        local_addresses.extend(matching_addresses);
                                    },
                                    Err(_e) => {}
                                }
                                addr = current_addr;
                            }

                            local_addresses.into_par_iter()
                        })
                        .collect::<Vec<u64>>()
                })
                .collect();

            Ok(results)
        } else {
            let result = unsafe { self.get_module_mem_range(pid, name) };
            match result {
                Ok(range_addresses) => {
                    if range_addresses.is_empty() {
                        return Err(errors::Error::InvalidInput("Or failed to get range address".to_string()));
                    }

                    let start = range_addresses[0];
                    let end = range_addresses[1];
                    let mut local_addresses = Vec::new();
                    let mut addr = start;
                    while addr + std::mem::size_of::<f64>() as u64 <= end {
                        let mut addrs_to_read = Vec::new();
                        let mut current_addr = addr;

                        while current_addr + std::mem::size_of::<f64>() as u64 <= end && addrs_to_read.len() < 200 {
                            addrs_to_read.push(current_addr);
                            current_addr += std::mem::size_of::<f64>() as u64;
                        }

                        match self.search_memory_double(pid, &addrs_to_read, value) {
                            Ok(matching_addresses) => {
                                local_addresses.extend(matching_addresses);
                            },
                            Err(_e) => {}
                        }
                        addr = current_addr;
                    }

                    Ok(local_addresses)
                },
                Err(e) => Err(e),
            }
        }
    }

    fn search_values_group_int(&self, pid: i32, values: Split<char>, regions: Vec<MemoryRegion>, name: String) -> Vec<Vec<(u64, i32)>> {
        let parsed_values: Vec<i32> = values.map(|v| v.parse().expect("error converting to number")).collect();
        let initial_value_addrs = self.search_value_int(pid, parsed_values[0], regions.clone(), name.clone()).expect("error searching group numbers");
        let mut result = Vec::new();
        let mut buf = vec![0u8; 4];

        for addr in initial_value_addrs.clone() {
            let mut res = Vec::new();

            for offset in (1..=700).rev() {
                let current_addr = addr.wrapping_sub(offset * 4);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_i32(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            match self.read_mem(pid, addr, &mut buf) {
                Ok(_) => {
                    let value = Device::extract_i32(&buf);
                    if parsed_values.contains(&value) {
                        res.push((addr, value));
                    }
                }
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
            }

            for offset in 1..=700 {
                let current_addr = addr.wrapping_add(offset * 4);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_i32(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            let all_values_found = parsed_values.iter().all(|&parsed_value| res.iter().any(|&(_, v)| v == parsed_value));

            if all_values_found {
                result.push(res);
            }
        }

        result
    }

    fn search_values_group_long(&self, pid: i32, values: Split<char>, regions: Vec<MemoryRegion>, name: String) -> Vec<Vec<(u64, i64)>> {
        let parsed_values: Vec<i64> = values.map(|v| v.parse().expect("error converting to number")).collect();
        let initial_value_addrs = self.search_value_long(pid, parsed_values[0], regions.clone(), name.clone()).expect("error searching group numbers");
        let mut result = Vec::new();
        let mut buf = vec![0u8; 8];

        for addr in initial_value_addrs.clone() {
            let mut res = Vec::new();

            for offset in (1..=700).rev() {
                let current_addr = addr.wrapping_sub(offset * 8);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_i64(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            match self.read_mem(pid, addr, &mut buf) {
                Ok(_) => {
                    let value = Device::extract_i64(&buf);
                    if parsed_values.contains(&value) {
                        res.push((addr, value));
                    }
                }
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
            }

            for offset in 1..=700 {
                let current_addr = addr.wrapping_add(offset * 8);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_i64(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            let all_values_found = parsed_values.iter().all(|&parsed_value| res.iter().any(|&(_, v)| v == parsed_value));

            if all_values_found {
                result.push(res);
            }
        }
        result
    }

    fn search_values_group_float(&self, pid: i32, values: Split<char>, regions: Vec<MemoryRegion>, name: String) -> Vec<Vec<(u64, f32)>> {
        let parsed_values: Vec<f32> = values.map(|v| v.parse().expect("error converting to number")).collect();
        let initial_value_addrs = self.search_value_float(pid, parsed_values[0], regions.clone(), name.clone()).expect("error searching group numbers");
        let mut result = Vec::new();
        let mut buf = vec![0u8; 4];

        for addr in initial_value_addrs.clone() {
            let mut res = Vec::new();

            for offset in (1..=700).rev() {
                let current_addr = addr.wrapping_sub(offset * 4);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_f32(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            match self.read_mem(pid, addr, &mut buf) {
                Ok(_) => {
                    let value = Device::extract_f32(&buf);
                    if parsed_values.contains(&value) {
                        res.push((addr, value));
                    }
                }
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
            }

            for offset in 1..=700 {
                let current_addr = addr.wrapping_add(offset * 4);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_f32(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            let all_values_found = parsed_values.iter().all(|&parsed_value| res.iter().any(|&(_, v)| v == parsed_value));

            if all_values_found {
                result.push(res);
            }
        }
        result
    }

    fn search_values_group_double(&self, pid: i32, values: Split<char>, regions: Vec<MemoryRegion>, name: String) -> Vec<Vec<(u64, f64)>> {
        let parsed_values: Vec<f64> = values.map(|v| v.parse().expect("error converting to number")).collect();
        let initial_value_addrs = self.search_value_double(pid, parsed_values[0], regions.clone(), name.clone()).expect("error searching group numbers");
        let mut result = Vec::new();
        let mut buf = vec![0u8; 8];

        for addr in initial_value_addrs.clone() {
            let mut res = Vec::new();

            for offset in (1..=700).rev() {
                let current_addr = addr.wrapping_sub(offset * 8);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_f64(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            match self.read_mem(pid, addr, &mut buf) {
                Ok(_) => {
                    let value = Device::extract_f64(&buf);
                    if parsed_values.contains(&value) {
                        res.push((addr, value));
                    }
                }
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
            }

            for offset in 1..=700 {
                let current_addr = addr.wrapping_add(offset * 8);
                match self.read_mem(pid, current_addr, &mut buf) {
                    Ok(_) => {
                        let value = Device::extract_f64(&buf);
                        if parsed_values.contains(&value) {
                            res.push((current_addr, value));
                        }
                    }
                    Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
                }
            }

            let all_values_found = parsed_values.iter().all(|&parsed_value| res.iter().any(|&(_, v)| v == parsed_value));

            if all_values_found {
                result.push(res);
            }
        }
        result
    }

    /// get the memory map of a process.
    pub fn get_mem_map(&self, pid: i32, phy_only: bool) -> Result<Vec<MapsEntry>> {
        let count = self.get_mem_map_count(pid)?;
        let buf_len = 8 + (8 + 8 + 4 + 512) * (count + 50);
        let mut buf = vec![0u8; buf_len];
        buf[0..8].copy_from_slice(&(pid as i64).to_ne_bytes());
        buf[8..16].copy_from_slice(&512usize.to_ne_bytes());
        buf[16..24].copy_from_slice(&buf_len.to_ne_bytes());

        let unfinished = nix::errno::Errno::result(unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(
                    RWMEM_MAGIC,
                    IOCTL_GET_PROCESS_MAPS_LIST,
                    std::mem::size_of::<usize>()
                ),
                buf.as_mut_ptr(),
                buf.len(),
            )
        })?;
        if unfinished != 0 {
            return Err(errors::Error::MapsTooLong);
        }
        let mut cursor = Cursor::new(buf);
        let real_count = cursor.read_u64::<NativeEndian>()?;
        let mut result = Vec::with_capacity(real_count as usize);
        for _ in 0..real_count {
            let start = cursor.read_u64::<NativeEndian>()?;
            let end = cursor.read_u64::<NativeEndian>()?;
            let read_permission = cursor.read_u8()? != 0;
            let write_permission = cursor.read_u8()? != 0;
            let execute_permission = cursor.read_u8()? != 0;
            let shared = cursor.read_u8()? != 0;
            let mut name = [0u8; 512];
            cursor.read_exact(&mut name)?;
            let mut name_length = 512usize;
            for i in 0..512 {
                if name[i] == 0 {
                    name_length = i;
                    break;
                }
            }
            let name = String::from_utf8_lossy(&name[0..name_length]).to_string();
            if phy_only {
                let is_mem_phy = self.is_mem_phy(pid, start, end)?;
                let mut is_last_phy = false;
                let mut begin_phy = 0u64;
                for (i, is_phy) in is_mem_phy.iter().enumerate() {
                    if *is_phy {
                        if !is_last_phy {
                            begin_phy = start + i as u64 * 0x1000;
                            is_last_phy = true;
                        }
                    } else {
                        if is_last_phy {
                            let entry = MapsEntry {
                                start: begin_phy,
                                end: start + i as u64 * 0x1000,
                                read_permission,
                                write_permission,
                                execute_permission,
                                shared,
                                name: name.clone(),
                            };
                            is_last_phy = false;
                            result.push(entry);
                        }
                    }
                }
                if is_last_phy {
                    let entry = MapsEntry {
                        start: begin_phy,
                        end,
                        read_permission,
                        write_permission,
                        execute_permission,
                        shared,
                        name,
                    };
                    result.push(entry);
                }
            } else {
                let entry = MapsEntry {
                    start,
                    end,
                    read_permission,
                    write_permission,
                    execute_permission,
                    shared,
                    name,
                };
                result.push(entry);
            }
        }
        Ok(result)
    }

    /// get the count of memory map entries.
    fn get_mem_map_count(&self, pid: i32) -> Result<usize> {
        let pid_buf = &mut [0u8; 8];
        pid_buf.copy_from_slice(&(pid as i64).to_ne_bytes());
        let count = nix::errno::Errno::result( unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(
                    RWMEM_MAGIC,
                    IOCTL_GET_PROCESS_MAPS_COUNT,
                    std::mem::size_of::<usize>()
                ),
                pid_buf.as_ptr(),
                8,
            )
        })?;
        Ok(count as usize)
    }

    /// check if the memory is physical.
    /// begin_addr and end_addr must be page aligned.
    /// return a bitvec, each bit represents a page.
    pub fn is_mem_phy(&self, pid: i32, begin_addr: u64, end_addr: u64) -> Result<BitVec<u8, Lsb0>> {
        if begin_addr & 0xfff != 0 {
            return Err(errors::Error::NotAligned);
        }
        if end_addr & 0xfff != 0 {
            return Err(errors::Error::NotAligned);
        }
        if begin_addr >= end_addr {
            return Err(errors::Error::BeginLargerThanEnd(begin_addr, end_addr));
        }
        let buf_size = max(24, ((end_addr >> 12) - (begin_addr >> 12) + 7) / 8) as usize;
        let mut buf = vec![0u8; buf_size];
        buf[0..8].copy_from_slice(&(pid as i64).to_ne_bytes());
        buf[8..16].copy_from_slice(&begin_addr.to_ne_bytes());
        buf[16..24].copy_from_slice(&end_addr.to_ne_bytes());
        nix::errno::Errno::result(unsafe {
            libc::ioctl(
                self.fd,
                request_code_readwrite!(
                    RWMEM_MAGIC,
                    IOCTL_CHECK_PROCESS_ADDR_PHY,
                    std::mem::size_of::<usize>()
                ),
                buf.as_mut_ptr(),
                buf_size,
            )
        })?;
        let mut result = BitVec::<u8, Lsb0>::from_vec(buf);
        result.truncate(((end_addr >> 12) - (begin_addr >> 12)) as usize);
        Ok(result)
    }

    pub fn extract_i32(buf: &[u8]) -> i32 {
        i32::from_ne_bytes(buf[0..4].try_into().unwrap())
    }

    pub fn extract_i64(buf: &[u8]) -> i64 {
        i64::from_ne_bytes(buf[0..8].try_into().unwrap())
    }

    pub fn extract_f32(buf: &[u8]) -> f32 {
        f32::from_ne_bytes(buf[0..4].try_into().unwrap())
    }

    pub fn extract_f64(buf: &[u8]) -> f64 {
        f64::from_ne_bytes(buf[0..8].try_into().unwrap())
    }

    fn get_maps(&self, pid: i32, regions: Vec<MemoryRegion>) -> Result<Vec<MapsEntry>> {
        let maps = self.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();
        Ok(maps)
    }

    pub fn disassemble_64(&self, pid: i32, addr: u64) -> Result<Vec<String>> {
        let mut buffers = Vec::new();
        let mut buf = vec![0u8; 8];

        for offset in (1..=1000).rev() {
            let current_addr = addr.wrapping_sub(offset * 8);
            match self.read_mem(pid, current_addr, &mut buf) {
                Ok(_) => buffers.push((current_addr, buf.clone())),
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
            }
        }

        match self.read_mem(pid, addr, &mut buf) {
            Ok(_) => buffers.push((addr, buf.clone())),
            Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
        }

        for offset in 1..=1000 {
            let current_addr = addr.wrapping_add(offset * 8);
            match self.read_mem(pid, current_addr, &mut buf) {
                Ok(_) => buffers.push((current_addr, buf.clone())),
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
            }
        }

        buffers.sort_by_key(|&(addr, _)| addr);

        let mut big_buffer = Vec::new();
        let mut base_addr = 0;
        if let Some((first_addr, _)) = buffers.first() {
            base_addr = *first_addr;
        }

        for (_, buf) in buffers {
            big_buffer.extend_from_slice(&buf);
        }

        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(|e| errors::Error::CapstoneError(e.to_string()))?;

        let insns = cs.disasm_all(&big_buffer, base_addr)
            .map_err(|e| errors::Error::CapstoneError(e.to_string()))?;

        let mut instructions = Vec::new();
        for i in insns.iter() {
            instructions.push(format!("{}", i));
        }

        Ok(instructions)
    }

    pub fn disassemble_32(&self, pid: i32, addr: u64) -> Result<Vec<String>> {
        let mut buffers = Vec::new();
        let mut buf = vec![0u8; 4];

        for offset in (1..=1000).rev() {
            let current_addr = addr.wrapping_sub(offset * 4);
            match self.read_mem(pid, current_addr, &mut buf) {
                Ok(_) => buffers.push((current_addr, buf.clone())),
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
            }
        }

        match self.read_mem(pid, addr, &mut buf) {
            Ok(_) => buffers.push((addr, buf.clone())),
            Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", addr, e),
        }

        for offset in 1..=1000 {
            let current_addr = addr.wrapping_add(offset * 4);
            match self.read_mem(pid, current_addr, &mut buf) {
                Ok(_) => buffers.push((current_addr, buf.clone())),
                Err(e) => eprintln!("Failed to read memory at {:#x}: {:?}", current_addr, e),
            }
        }

        buffers.sort_by_key(|&(addr, _)| addr);

        let mut big_buffer = Vec::new();
        let mut base_addr = 0;
        if let Some((first_addr, _)) = buffers.first() {
            base_addr = *first_addr;
        }

        for (_, buf) in buffers {
            big_buffer.extend_from_slice(&buf);
        }

        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .map_err(|e| errors::Error::CapstoneError(e.to_string()))?;

        let insns = cs.disasm_all(&big_buffer, base_addr)
            .map_err(|e| errors::Error::CapstoneError(e.to_string()))?;

        let mut instructions = Vec::new();
        for i in insns.iter() {
            instructions.push(format!("{}", i));
        }

        Ok(instructions)
    }

    pub fn write_assembly(&self, pid: i32, addr: u64, assembly_code: String, is_64_bit: bool) -> Result<()> {

        if assembly_code.is_empty() {
            return Err(errors::Error::InvalidInput("Assembly code is empty".to_string()));
        }

        if addr == 0 {
            return Err(errors::Error::InvalidInput("Address is zero".to_string()));
        }

        let ks = if is_64_bit {
            Keystone::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
                .map_err(|e| errors::Error::KeystoneError(e.to_string()))?
        } else {
            Keystone::new(Arch::ARM, Mode::ARM)
                .map_err(|e| errors::Error::KeystoneError(e.to_string()))?
        };

        let machine_code = ks.asm(assembly_code, 0).map_err(|e| errors::Error::KeystoneError(e.to_string()))?;

        if machine_code.bytes.is_empty() {
            return Err(errors::Error::InvalidInput("Failed to assemble code".to_string()));
        }

        self.write_mem(pid, addr, &machine_code.bytes)
    }

    pub unsafe fn get_module_mem_range(&self, pid: i32, name: String) -> Result<Vec<u64>> {
        let c_string = CString::new(name);
        let mut params = ModuleRange {
            pid,
            name: [0; 256],
            address_base: 0,
            address_end: 0,
        };

        let c_string = c_string.unwrap();
        let name_bytes = c_string.as_bytes_with_nul();
        let name_len = name_bytes.len();
        ptr::copy_nonoverlapping(name_bytes.as_ptr(), params.name.as_mut_ptr() as *mut u8, name_len);

        let ret = libc::ioctl(
                self.fd,
                request_code_readwrite!(RWMEM_MAGIC, IOCTL_GET_MODULE_RANGE, std::mem::size_of::<ModuleRange>()),
                &mut params as *mut _ as *mut libc::c_void,
        );

        if ret < 0 {
            return Err(errors::Error::IoctlFailed);
        }

        let range_address_base = params.address_base;
        let range_address_end = params.address_end;

        Ok(vec![range_address_base, range_address_end])
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        nix::unistd::close(self.fd).unwrap();
    }
}

#[derive(Parser)]
#[command(name = "Android Memory Tool", version = "0.3.7", author = "yervant7", about = "Tool to read and write process memory on Android")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Read {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Number of bytes to read (must be 4 or 8)")]
        size: usize,
        #[arg(help = "Data type: int, long, float, double")]
        data_type: String,
    },
    WriteInt {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Value to write")]
        value: i32,
    },
    WriteLong {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Value to write")]
        value: i64,
    },
    WriteFloat {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Value to write")]
        value: f32,
    },
    WriteDouble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Value to write")]
        value: f64,
    },
    WriteAssembly {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Code assembly to write")]
        assembly_code: String,
        #[arg(help = "is 64 bits? (64 or 32)")]
        is_64_bits: String,
    },
    Maps {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory regions to get map (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
    },
    ModuleRange {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "name of module")]
        name: String,
    },
    Disassemble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory address")]
        addr: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchGroupInt {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "values")]
        values: String,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchGroupLong {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "values")]
        values: String,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchGroupFloat {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "values")]
        values: String,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchGroupDouble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "values")]
        values: String,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchInt {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Integer value to search")]
        value: i32,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchLong {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Long value to search")]
        value: i64,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchFloat {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Float value to search")]
        value: f32,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    SearchDouble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Double value to search")]
        value: f64,
        #[arg(help = "Memory regions to search (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterInt {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: i32,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterLong {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: i64,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterFloat {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: f32,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterDouble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: f64,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterGroupInt {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: String,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterGroupLong {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: String,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterGroupFloat {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: String,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
    FilterGroupDouble {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Value to filter")]
        expected_value: String,
        #[arg(help = "Path file to read and filter")]
        filename: String,
        #[arg(help = "Path to save output")]
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("Failed to open device: {:?}", e);
            return;
        }
    };

    match cli.command {
        Commands::Read { pid, addr, size, data_type } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let mut buf = vec![0u8; size];
            match device.read_mem(pid, addr, &mut buf) {
                Ok(_) => {
                    match data_type.as_str() {
                        "int" if size == 4 => {
                            let value = Device::extract_i32(&buf);
                            println!("Value: {}", value);
                        }
                        "long" if size == 8 => {
                            let value = Device::extract_i64(&buf);
                            println!("Value: {}", value);
                        }
                        "float" if size == 4 => {
                            let value = Device::extract_f32(&buf);
                            println!("Value: {}", value);
                        }
                        "double" if size == 4 => {
                            let value = Device::extract_f64(&buf);
                            println!("Value: {}", value);
                        }
                        _ => {
                            eprintln!("Invalid data type or size");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read memory: {:?}", e);
                }
            }
        }
        Commands::WriteInt { pid, addr, value } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let buf = value.to_ne_bytes();
            match device.write_mem(pid, addr, &buf) {
                Ok(_) => println!("Wrote value: {} to address: {:#x}", value, addr),
                Err(e) => eprintln!("Failed to write memory: {:?}", e),
            }
        }
        Commands::WriteLong { pid, addr, value } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let buf = value.to_ne_bytes();
            match device.write_mem(pid, addr, &buf) {
                Ok(_) => println!("Wrote value: {} to address: {:#x}", value, addr),
                Err(e) => eprintln!("Failed to write memory: {:?}", e),
            }
        }
        Commands::WriteFloat { pid, addr, value } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let buf = value.to_ne_bytes();
            match device.write_mem(pid, addr, &buf) {
                Ok(_) => println!("Wrote value: {} to address: {:#x}", value, addr),
                Err(e) => eprintln!("Failed to write memory: {:?}", e),
            }
        }
        Commands::WriteDouble { pid, addr, value } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let buf = value.to_ne_bytes();
            match device.write_mem(pid, addr, &buf) {
                Ok(_) => println!("Wrote value: {} to address: {:#x}", value, addr),
                Err(e) => eprintln!("Failed to write memory: {:?}", e),
            }
        }
        Commands::WriteAssembly {pid, addr, assembly_code, is_64_bits} => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let is_64_bit = if is_64_bits == "64" {true} else {false};
            match device.write_assembly(pid, addr, assembly_code.clone(), is_64_bit) {
                Ok(_) => println!("Wrote code: {} to address: {:#x}", assembly_code, addr),
                Err(e) => eprintln!("Failed to write memory: {:?}", e),
            }
        }
        Commands::Maps { pid, regions } => {
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let maps = match device.get_maps(pid, regions) {
                Ok(maps) => maps,
                Err(e) => {
                    eprintln!("Failed to get memory maps: {:?}", e);
                    return;
                }
            };
            for map in maps {
                println!("{:?}", map);
            }
        }
        Commands::ModuleRange { pid, name} => {
            let result = unsafe {
                device.get_module_mem_range(pid, name)
            };
            let result = result.unwrap();
            println!("Start: {:#x} End: {:#x}", result[0], result[1]);
        }
        Commands::Disassemble { pid, addr, path } => {
            let addr = match u64::from_str_radix(&addr.trim_start_matches("0x"), 16) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid hexadecimal address");
                    return;
                }
            };
            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            match device.disassemble_64(pid, addr) {
                Ok(instructions) => {
                    if instructions.is_empty() {
                        match device.disassemble_32(pid, addr) {
                            Ok(instructions) => {
                                for instruction in instructions {
                                    if let Err(e) = writeln!(file, "{}", instruction) {
                                        eprintln!("Failed to write to file: {:?}", e);
                                        return;
                                    }
                                }
                                println!("Disassemble32 finished check file: {}", path);
                            }
                            Err(e) => eprintln!("Failed to disassemble memory: {:?}", e),
                        }
                    } else {
                        for instruction in instructions {
                            if let Err(e) = writeln!(file, "{}", instruction) {
                                eprintln!("Failed to write to file: {:?}", e);
                                return;
                            }
                        }
                        println!("Disassemble64 finished check file: {}", path);
                        match device.disassemble_32(pid, addr) {
                            Ok(instructions) => {
                                for instruction in instructions {
                                    if let Err(e) = writeln!(file, "{}", instruction) {
                                        eprintln!("Failed to write to file: {:?}", e);
                                        return;
                                    }
                                }
                                println!("Disassemble32 finished check file: {}", path);
                            }
                            Err(e) => eprintln!("Failed to disassemble memory: {:?}", e),
                        }
                    }
                }
                Err(e) => eprintln!("Failed to disassemble memory: {:?}", e),
            }
        }
        Commands::SearchGroupInt { pid, values, regions, path } => {
            let start = Instant::now();

            let name = if regions.contains("lib") {
                regions.to_string()
            } else {
                "".to_string()
            };

            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();

            if values.contains(";") {
                println!("valid values")
            } else {
                eprintln!("Invalid values");
                return;
            }
            let values = values.split(';');

            let results = device.search_values_group_int(pid, values, regions, name);

            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };

            for vector in results {
                for (address, value) in vector {
                    if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                        eprintln!("Failed to write to file: {:?}", e);
                        return;
                    }
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchGroupLong { pid, values, regions, path } => {
            let start = Instant::now();

            let name = if regions.contains("lib") {
                regions.to_string()
            } else {
                "".to_string()
            };

            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();

            if values.contains(";") {
                println!("valid values")
            } else {
                eprintln!("Invalid values");
                return;
            }

            let values = values.split(';');

            let results = device.search_values_group_long(pid, values, regions, name);

            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };

            for vector in results {
                for (address, value) in vector {
                    if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                        eprintln!("Failed to write to file: {:?}", e);
                        return;
                    }
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchGroupFloat { pid, values, regions, path } => {
            let start = Instant::now();

            let name = if regions.contains("lib") {
                regions.to_string()
            } else {
                "".to_string()
            };

            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();

            if values.contains(";") {
                println!("valid values")
            } else {
                eprintln!("Invalid values");
                return;
            }

            let values = values.split(';');

            let results = device.search_values_group_float(pid, values, regions, name);

            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };

            for vector in results {
                for (address, value) in vector {
                    if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                        eprintln!("Failed to write to file: {:?}", e);
                        return;
                    }
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchGroupDouble { pid, values, regions, path } => {
            let start = Instant::now();

            let name = if regions.contains("lib") {
                regions.to_string()
            } else {
                "".to_string()
            };

            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();

            if values.contains(";") {
                println!("valid values")
            } else {
                eprintln!("Invalid values");
                return;
            }

            let values = values.split(';');

            let results = device.search_values_group_double(pid, values, regions, name);

            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };

            for vector in results {
                for (address, value) in vector {
                    if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                        eprintln!("Failed to write to file: {:?}", e);
                        return;
                    }
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchInt { pid, value, regions, path } => {
            let start = Instant::now();
            let name = if regions.clone().contains("lib") {
                regions.clone()
            } else {
                "".to_string()
            };
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let results = match device.search_value_int(pid, value, regions, name) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("Failed to search for int value: {:?}", e);
                    return;
                }
            };
            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            for address in results {
                if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchLong { pid, value, regions, path } => {
            let start = Instant::now();
            let name = if regions.clone().contains("lib") {
                regions.clone()
            } else {
                "".to_string()
            };
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let results = match device.search_value_long(pid, value, regions, name) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("Failed to search for long value: {:?}", e);
                    return;
                }
            };
            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            for address in results {
                if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchFloat { pid, value, regions, path } => {
            let start = Instant::now();
            let name = if regions.clone().contains("lib") {
                regions.clone()
            } else {
                "".to_string()
            };
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let results = match device.search_value_float(pid, value, regions, name) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("Failed to search for float value: {:?}", e);
                    return;
                }
            };
            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            for address in results {
                if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::SearchDouble { pid, value, regions, path } => {
            let start = Instant::now();
            let name = if regions.clone().contains("lib") {
                regions.clone()
            } else {
                "".to_string()
            };
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let results = match device.search_value_double(pid, value, regions, name) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("Failed to search for float value: {:?}", e);
                    return;
                }
            };
            let mut file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            for address in results {
                if let Err(e) = writeln!(file, "{:#x} {}", address, value) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            let duration = start.elapsed();
            println!("Search finished time {:?} check file: {}", duration, path);
        }
        Commands::FilterInt { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let addresses: Vec<u64> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 4];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_i32(&buf);
                        if value == expected_value {
                            return Some(address);
                        }
                    }
                    None
                })
                .collect();

            for address in addresses {
                writeln!(file2, "{:#x}", address).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }

        Commands::FilterLong { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let addresses: Vec<u64> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 8];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_i64(&buf);
                        if value == expected_value {
                            return Some(address);
                        }
                    }
                    None
                })
                .collect();

            for address in addresses {
                writeln!(file2, "{:#x}", address).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }

        Commands::FilterFloat { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let addresses: Vec<u64> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 4];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_f32(&buf);
                        if value == expected_value {
                            return Some(address);
                        }
                    }
                    None
                })
                .collect();

            for address in addresses {
                writeln!(file2, "{:#x}", address).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }
        Commands::FilterDouble { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let addresses: Vec<u64> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 8];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_f64(&buf);
                        if value == expected_value {
                            return Some(address);
                        }
                    }
                    None
                })
                .collect();

            for address in addresses {
                writeln!(file2, "{:#x}", address).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }
        Commands::FilterGroupInt { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };

            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let values = expected_value.split(";");

            let parsed_values: Vec<i32> = values.map(|v| v.parse().expect("error converting to number")).collect();

            let result: Vec<(u64, i32)> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 4];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_i32(&buf);
                        if parsed_values.contains(&value) {
                            return Some((address, value));
                        }
                    }
                    None
                })
                .collect();

            for (address, value) in result {
                writeln!(file2, "{:#x} {}", address, value).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }

        Commands::FilterGroupLong { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let values = expected_value.split(";");

            let parsed_values: Vec<i64> = values.map(|v| v.parse().expect("error converting to number")).collect();

            let result: Vec<(u64, i64)> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 8];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_i64(&buf);
                        if parsed_values.contains(&value) {
                            return Some((address, value));
                        }
                    }
                    None
                })
                .collect();

            for (address, value) in result {
                writeln!(file2, "{:#x} {}", address, value).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }

        Commands::FilterGroupFloat { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let values = expected_value.split(";");

            let parsed_values: Vec<f32> = values.map(|v| v.parse().expect("error converting to number")).collect();

            let result: Vec<(u64, f32)> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 4];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_f32(&buf);
                        if parsed_values.contains(&value) {
                            return Some((address, value));
                        }
                    }
                    None
                })
                .collect();

            for (address, value) in result {
                writeln!(file2, "{:#x} {}", address, value).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }
        Commands::FilterGroupDouble { pid, expected_value, filename, path } => {
            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };
            let mut file2 = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {:?}", e);
                    return;
                }
            };
            let mut addresses = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let mut tmp = line.split_whitespace();
                        if let Some(address_str) = tmp.next() {
                            addresses.push(address_str.to_string());
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {:?}", e),
                }
            }

            let values = expected_value.split(";");

            let parsed_values: Vec<f64> = values.map(|v| v.parse().expect("error converting to number")).collect();

            let result: Vec<(u64, f64)> = addresses.par_iter()
                .filter_map(|line| {
                    let address = u64::from_str_radix(&line.trim_start_matches("0x"), 16).ok()?;
                    let mut buf = [0u8; 8];
                    if device.read_mem(pid, address, &mut buf).is_ok() {
                        let value = Device::extract_f64(&buf);
                        if parsed_values.contains(&value) {
                            return Some((address, value));
                        }
                    }
                    None
                })
                .collect();

            for (address, value) in result {
                writeln!(file2, "{:#x} {}", address, value).expect("Failed to write to file");
            }
            println!("Filter finished check file: {}", path);
        }
    }
}
