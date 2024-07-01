use std::cmp::max;
use bitvec::{order::Lsb0, vec::BitVec};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::os::unix::io::RawFd;
use std::path::Path;
use byteorder::{NativeEndian, ReadBytesExt};
use nix::request_code_readwrite;
use nix::fcntl;
use nix::sys::stat;
use nix::errno::Errno;
use rayon::prelude::*;

mod errors;

type Result<T> = std::result::Result<T, errors::Error>;

const RWMEM_MAGIC: u8 = 100;
const IOCTL_GET_PROCESS_MAPS_COUNT: u8 = 0;
const IOCTL_GET_PROCESS_MAPS_LIST: u8 = 1;
const IOCTL_CHECK_PROCESS_ADDR_PHY: u8 = 2;

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

    fn search_value_int(&self, pid: i32, value: i32, regions: Vec<MemoryRegion>) -> Result<Vec<u64>> {
        let maps = self.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();

        let addresses: Vec<u64> = maps.par_iter()
            .flat_map(|map| {
                let mut local_addresses = Vec::new();
                let mut addr = map.start;
                while addr < map.end {
                    let mut buf = [0u8; std::mem::size_of::<i32>()];
                    if self.read_mem(pid, addr, &mut buf).is_ok() {
                        let read_value = Device::extract_i32(&buf);
                        if read_value == value {
                            local_addresses.push(addr);
                        }
                    }
                    addr += std::mem::size_of::<i32>() as u64;
                }
                local_addresses
            })
            .collect();

        Ok(addresses)
    }

    fn search_value_long(&self, pid: i32, value: i64, regions: Vec<MemoryRegion>) -> Result<Vec<u64>> {
        let maps = self.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();

        let addresses: Vec<u64> = maps.par_iter()
            .flat_map(|map| {
                let mut local_addresses = Vec::new();
                let mut addr = map.start;
                while addr < map.end {
                    let mut buf = [0u8; std::mem::size_of::<i64>()];
                    if self.read_mem(pid, addr, &mut buf).is_ok() {
                        let read_value = Device::extract_i64(&buf);
                        if read_value == value {
                            local_addresses.push(addr);
                        }
                    }
                    addr += std::mem::size_of::<i64>() as u64;
                }
                local_addresses
            })
            .collect();

        Ok(addresses)
    }

    fn search_value_float(&self, pid: i32, value: f32, regions: Vec<MemoryRegion>) -> Result<Vec<u64>> {
        let maps = self.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();

        let addresses: Vec<u64> = maps.par_iter()
            .flat_map(|map| {
                let mut local_addresses = Vec::new();
                let mut addr = map.start;
                while addr < map.end {
                    let mut buf = [0u8; std::mem::size_of::<f32>()];
                    if self.read_mem(pid, addr, &mut buf).is_ok() {
                        let read_value = Device::extract_f32(&buf);
                        if read_value == value {
                            local_addresses.push(addr);
                        }
                    }
                    addr += std::mem::size_of::<f32>() as u64;
                }
                local_addresses
            })
            .collect();

        Ok(addresses)
    }

    fn get_maps(&self, pid: i32, regions: Vec<MemoryRegion>) -> Result<Vec<MapsEntry>> {
        let maps = self.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();
        Ok(maps)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        nix::unistd::close(self.fd).unwrap();
    }
}

#[derive(Parser)]
#[command(name = "Android Memory Tool", version = "0.1.5", author = "yervant7 and ri-char", about = "Tool to read and write process memory on Android")]
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
        #[arg(help = "Data type: int, long, float")]
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
    Maps {
        #[arg(help = "Process ID")]
        pid: i32,
        #[arg(help = "Memory regions to get map (e.g., C_ALLOC,C_BSS, etc.)")]
        regions: String,
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
    }
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
        Commands::SearchInt { pid, value, regions, path } => {
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let addresses = match device.search_value_int(pid, value, regions) {
                Ok(addrs) => addrs,
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
            for addr in &addresses {
                if let Err(e) = writeln!(file, "{:#x}", addr) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            println!("Search finished check file: {}", path);
        }
        Commands::SearchLong { pid, value, regions, path } => {
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let addresses = match device.search_value_long(pid, value, regions) {
                Ok(addrs) => addrs,
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
            for addr in &addresses {
                if let Err(e) = writeln!(file, "{:#x}", addr) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            println!("Search finished check file: {}", path);
        }
        Commands::SearchFloat { pid, value, regions, path } => {
            let regions = regions.split(',')
                .filter_map(|s| MemoryRegion::from_str(s))
                .collect::<Vec<_>>();
            let addresses = match device.search_value_float(pid, value, regions) {
                Ok(addrs) => addrs,
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
            for addr in &addresses {
                if let Err(e) = writeln!(file, "{:#x}", addr) {
                    eprintln!("Failed to write to file: {:?}", e);
                    return;
                }
            }
            println!("Search finished check file: {}", path);
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
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();

            let addresses: Vec<u64> = lines.par_iter()
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
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();

            let addresses: Vec<u64> = lines.par_iter()
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
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();

            let addresses: Vec<u64> = lines.par_iter()
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
    }
}
