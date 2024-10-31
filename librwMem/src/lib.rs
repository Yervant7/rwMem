extern crate jni;

use std::cmp::max;
use bitvec::{order::Lsb0, vec::BitVec};
use std::io::{Cursor, Read};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::str;
use byteorder::{NativeEndian, ReadBytesExt};
use nix::request_code_readwrite;
use nix::fcntl;
use nix::sys::stat;
use nix::errno::{Errno};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use jni::JNIEnv;
use jni::objects::{JClass, JLongArray, JObject, JObjectArray, JString, ReleaseMode};
use jni::sys::{jint, jlong, jsize};
use std::any::TypeId;
use std::convert::TryInto;
use std::ops::{Add, Sub};
use bitvec::macros::internal::funty::Fundamental;
use android_logger::Config;
use bytemuck::{Pod, try_from_bytes};
use num_traits::cast::FromPrimitive;
use log::error;

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

#[derive(Clone, Copy)]
enum ScanType {
    AccurateVal,
    LargerThanVal,
    LessThanVal,
    BetweenVal,
}

#[derive(Debug, Clone, Copy)]
struct AddrResultInfo {
    addr: u64,
    size: usize,
}

struct MemSearchSafeWorkSecWrapper {
    entries: Vec<MapsEntry>,
    current_index: Arc<AtomicUsize>,
}

impl MemSearchSafeWorkSecWrapper {
    pub fn new() -> Self {
        MemSearchSafeWorkSecWrapper {
            entries: Vec::new(),
            current_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn get_next_work_section(&self) -> Option<(u64, u64)> {
        let index = self.current_index.fetch_add(1, Ordering::SeqCst);
        if index < self.entries.len() {
            let entry = &self.entries[index];
            Some((entry.start, entry.end - entry.start))
        } else {
            None
        }
    }

    pub fn load_memory_sections(&mut self, proxy: Arc<Device>, pid: i32, regions: Vec<MemoryRegion>) -> Result<()> {
        let mem_map = proxy.get_mem_map(pid, false)?
            .into_iter()
            .filter(|map| regions.iter().any(|region| region.matches(map)))
            .collect::<Vec<_>>();
        self.entries = mem_map;
        Ok(())
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
        android_logger::init_once(Config::default().with_tag("rwMem"));
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
    fn search_value<T>(
            self: Arc<Self>,
            pid: i32,
            wait_scan_mem_sec_list: Arc<Mutex<MemSearchSafeWorkSecWrapper>>,
            value1: T,
            value2: T,
            error_range: f32,
            scan_type: ScanType,
            n_thread_count: usize,
            scan_align_bytes: usize,
            force_stop_signal: Arc<AtomicBool>,
        ) -> Result<Vec<AddrResultInfo>>
        where
            T: Copy + PartialOrd + Send + Pod + Sub<Output = T> + Add<Output = T> + FromPrimitive + 'static,
    {
        let result_list = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..n_thread_count {
            let wait_scan_mem_sec_list = Arc::clone(&wait_scan_mem_sec_list);
            let result_list = Arc::clone(&result_list);
            let force_stop_signal = Arc::clone(&force_stop_signal);
            let self_arc = Arc::clone(&self);

            let handle = thread::spawn(move || {
                while !force_stop_signal.load(Ordering::Acquire) {
                    let (start_addr, size) = match wait_scan_mem_sec_list.lock().unwrap().get_next_work_section() {
                        Some(section) => section,
                        None => break,
                    };

                    let mut buffer = vec![0u8; size as usize];
                    if let Err(_) = self_arc.read_mem(pid, start_addr, &mut buffer) {
                        continue;
                    }

                    let mut local_results = Vec::new();
                    for (i, chunk) in buffer.chunks(scan_align_bytes).enumerate() {
                        let addr = start_addr + (i * scan_align_bytes) as u64;

                        let matches = if TypeId::of::<T>() == TypeId::of::<f32>() || TypeId::of::<T>() == TypeId::of::<f64>() {
                            let error_range_t = T::from_f32(error_range).unwrap();
                            let lower_bound = value1 - error_range_t;
                            let upper_bound = value1 + error_range_t;

                            match scan_type {
                                ScanType::AccurateVal => {
                                    if let Ok(value) = try_from_bytes::<T>(chunk) {
                                        *value >= lower_bound && *value <= upper_bound
                                    } else {
                                        false
                                    }
                                }
                                ScanType::LargerThanVal => try_from_bytes::<T>(chunk).map_or(false, |value| *value > value1),
                                ScanType::LessThanVal => try_from_bytes::<T>(chunk).map_or(false, |value| *value < value1),
                                ScanType::BetweenVal => {
                                    let val_min = if value1 < value2 { value1 } else { value2 };
                                    let val_max = if value1 > value2 { value1 } else { value2 };
                                    try_from_bytes::<T>(chunk).map_or(false, |value| *value >= val_min && *value <= val_max)
                                }
                            }
                        } else {
                            match scan_type {
                                ScanType::AccurateVal => try_from_bytes::<T>(chunk).map_or(false, |value| *value == value1),
                                ScanType::LargerThanVal => try_from_bytes::<T>(chunk).map_or(false, |value| *value > value1),
                                ScanType::LessThanVal => try_from_bytes::<T>(chunk).map_or(false, |value| *value < value1),
                                ScanType::BetweenVal => {
                                    let val_min = if value1 < value2 { value1 } else { value2 };
                                    let val_max = if value1 > value2 { value1 } else { value2 };
                                    try_from_bytes::<T>(chunk).map_or(false, |value| *value >= val_min && *value <= val_max)
                                }
                            }
                        };

                        if matches {
                            local_results.push(AddrResultInfo {
                                addr,
                                size: std::mem::size_of::<T>(),
                            });
                        }
                    }

                    let mut result_list = result_list.lock().unwrap();
                    result_list.extend(local_results);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let final_results = Arc::try_unwrap(result_list).unwrap().into_inner().unwrap();
        Ok(final_results)
    }

    fn search_addr_next_value<T>(
        self: Arc<Self>,
        pid: i32,
        wait_scan_mem_sec_list: Arc<Mutex<Vec<AddrResultInfo>>>,
        value1: T,
        value2: T,
        error_range: f32,
        scan_type: ScanType,
        n_thread_count: usize,
        force_stop_signal: Arc<AtomicBool>,
    ) -> Result<Vec<AddrResultInfo>>
    where
        T: Copy + PartialOrd + Send + Pod + Sub<Output = T> + Add<Output = T> + FromPrimitive + 'static,
    {
        let result_list = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..n_thread_count {
            let wait_scan_mem_sec_list = Arc::clone(&wait_scan_mem_sec_list);
            let result_list = Arc::clone(&result_list);
            let force_stop_signal = Arc::clone(&force_stop_signal);
            let self_arc = Arc::clone(&self);

            let handle = thread::spawn(move || {
                while !force_stop_signal.load(Ordering::Acquire) {

                    let maybe_section = {
                        let mut res = wait_scan_mem_sec_list.lock().unwrap();
                        res.pop()
                    };

                    let section = match maybe_section {
                        Some(section) => section,
                        None => break,
                    };

                    let mut buf = vec![0u8; section.size as usize];
                    if let Err(_) = self_arc.read_mem(pid, section.addr, &mut buf) {
                        continue;
                    }

                    let addr = section.addr;
                    let matches = if TypeId::of::<T>() == TypeId::of::<f32>() || TypeId::of::<T>() == TypeId::of::<f64>() {
                        match scan_type {
                            ScanType::AccurateVal => {
                                if let Ok(temp) = try_from_bytes::<T>(&buf) {
                                    let error_range_t = T::from_f32(error_range).unwrap();
                                    let lower_bound = value1 - error_range_t;
                                    let upper_bound = value1 + error_range_t;
                                    lower_bound <= *temp && *temp <= upper_bound
                                } else {
                                    false
                                }
                            }
                            ScanType::LargerThanVal => try_from_bytes::<T>(&buf).map_or(false, |temp| *temp >= value1),
                            ScanType::LessThanVal => try_from_bytes::<T>(&buf).map_or(false, |temp| *temp <= value1),
                            ScanType::BetweenVal => {
                                let val_min = if value1 < value2 { value1 } else { value2 };
                                let val_max = if value1 > value2 { value1 } else { value2 };
                                try_from_bytes::<T>(&buf).map_or(false, |temp| val_min <= *temp && *temp <= val_max)
                            }
                        }
                    } else {
                        match scan_type {
                            ScanType::AccurateVal => try_from_bytes::<T>(&buf).map_or(false, |temp| *temp == value1),
                            ScanType::LargerThanVal => try_from_bytes::<T>(&buf).map_or(false, |temp| *temp > value1),
                            ScanType::LessThanVal => try_from_bytes::<T>(&buf).map_or(false, |temp| *temp < value1),
                            ScanType::BetweenVal => {
                                let val_min = if value1 < value2 { value1 } else { value2 };
                                let val_max = if value1 > value2 { value1 } else { value2 };
                                try_from_bytes::<T>(&buf).map_or(false, |temp| val_min <= *temp && *temp <= val_max)
                            }
                        }
                    };

                    if matches {
                        let mut result_list_lock = result_list.lock().unwrap();
                        result_list_lock.push(AddrResultInfo {
                            addr,
                            size: std::mem::size_of::<T>(),
                        });
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let final_results = Arc::try_unwrap(result_list).unwrap().into_inner().unwrap();
        Ok(final_results)
    }

    fn search_group_values<T>(
        self: Arc<Self>,
        pid: i32,
        wait_scan_mem_sec_list: Arc<Mutex<MemSearchSafeWorkSecWrapper>>,
        values: Vec<T>,
        proximity_limit: usize,
        error_range: Option<f32>,
        n_thread_count: usize,
        scan_align_bytes: usize,
        force_stop_signal: Arc<AtomicBool>,
    ) -> Result<Vec<AddrResultInfo>>
    where
        T: Copy + PartialOrd + Send + Pod + Sub<Output = T> + Add<Output = T> + FromPrimitive + 'static,
    {
        let result_list = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        let values_ref = values;
        for _ in 0..n_thread_count {
            let wait_scan_mem_sec_list = Arc::clone(&wait_scan_mem_sec_list);
            let result_list = Arc::clone(&result_list);
            let force_stop_signal = Arc::clone(&force_stop_signal);
            let self_arc = Arc::clone(&self);
            let values_clone = values_ref.to_vec();
            let handle = thread::spawn(move || {
                while !force_stop_signal.load(Ordering::Acquire) {
                    let (start_addr, size) = match wait_scan_mem_sec_list.lock().unwrap().get_next_work_section()  {
                        Some(section) => section,
                        None => break,
                    };

                    let mut buffer = vec![0u8; size as usize];
                    if let Err(_) = self_arc.read_mem(pid, start_addr, &mut buffer) {
                        continue;
                    }

                    let mut local_results = Vec::new();
                    for (i, chunk) in buffer.chunks(scan_align_bytes).enumerate() {
                        let addr = start_addr + (i * scan_align_bytes) as u64;

                        for value in &values_clone {
                            let matches = if TypeId::of::<T>() == TypeId::of::<f32>() || TypeId::of::<T>() == TypeId::of::<f64>() {
                                if let Some(error_range) = error_range {
                                    let error_range_t = T::from_f32(error_range).unwrap();
                                    let lower_bound = *value - error_range_t;
                                    let upper_bound = *value + error_range_t;

                                    try_from_bytes::<T>(chunk).map_or(false, |v| *v >= lower_bound && *v <= upper_bound)
                                } else {
                                    try_from_bytes::<T>(chunk).map_or(false, |v| *v == *value)
                                }
                            } else {
                                try_from_bytes::<T>(chunk).map_or(false, |v| *v == *value)
                            };

                            if matches {
                                local_results.push(AddrResultInfo {
                                    addr,
                                    size: std::mem::size_of::<T>(),
                                });
                            }
                        }
                    }

                    let mut result_list = result_list.lock().unwrap();
                    local_results.sort_by_key(|r| r.addr);

                    let mut final_results = Vec::new();
                    let mut last_addr: Option<u64> = None;

                    for result in local_results {
                        if !last_addr.is_none() && (result.addr - last_addr.unwrap()) as usize <= proximity_limit {
                            final_results.push(result);
                        }
                        last_addr = Some(result.addr.clone());
                    }
                    result_list.extend(final_results);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let final_results = Arc::try_unwrap(result_list).unwrap().into_inner().unwrap();
        Ok(final_results)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        nix::unistd::close(self.fd).unwrap();
    }
}

fn getscantype(type_id: i32) -> ScanType {
    match type_id {
        0 => ScanType::AccurateVal,
        1 => ScanType::LargerThanVal,
        2 => ScanType::LessThanVal,
        3 => ScanType::BetweenVal,
        _ => ScanType::AccurateVal,
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_readmultiple<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    addresses: JLongArray<'a>,
    pid: jlong,
    datatype: JString<'a>,
) -> JObjectArray<'a> {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string!").into();
    let arraysize: jsize = env.get_array_length(&addresses).expect("Couldn't get Java longarray!");

    let mut addrs: Vec<u64> = vec![0; arraysize as usize];
    let target_pid: i32 = pid.try_into().unwrap();
    let elements = env.get_array_elements(&addresses, ReleaseMode::NoCopyBack).unwrap();

    for i in 0..arraysize {
        addrs[i as usize] = elements[i as usize].as_u64();
    }

    let result = env.new_object_array(arraysize, "java/lang/String", JObject::null()).unwrap();

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => dev,
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return result;
        }
    };

    let mut valuesstr: Vec<String> = Vec::new();

    match typ.as_str() {
        "int" => {
            for addr in addrs {
                let mut buf = vec![0u8; 4];
                device.read_mem(target_pid, addr, &mut buf).unwrap();
                let value = i32::from_ne_bytes(buf.try_into().unwrap());
                valuesstr.push(value.to_string());
            }
        }
        "long" => {
            for addr in addrs {
                let mut buf = vec![0u8; 8];
                device.read_mem(target_pid, addr, &mut buf).unwrap();
                let value = i64::from_ne_bytes(buf.try_into().unwrap());
                valuesstr.push(value.to_string());
            }
        }
        "float" => {
            for addr in addrs {
                let mut buf = vec![0u8; 4];
                device.read_mem(target_pid, addr, &mut buf).unwrap();
                let value = f32::from_ne_bytes(buf.try_into().unwrap());
                valuesstr.push(value.to_string());
            }
        }
        "double" => {
            for addr in addrs {
                let mut buf = vec![0u8; 8];
                device.read_mem(target_pid, addr, &mut buf).unwrap();
                let value = f64::from_ne_bytes(buf.try_into().unwrap());
                valuesstr.push(value.to_string());
            }
        }
        _ => {
            error!("Invalid data type");
            return result;
        }
    }

    for j in 0..valuesstr.len() {
        let java_string = env.new_string(&valuesstr[j]).unwrap();
        env.set_object_array_element(&result, j as jsize, java_string).unwrap();
    }

    result
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_writemultiple<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    addresses: JLongArray<'a>,
    pid: jlong,
    datatype: JString<'a>,
    value: JString<'a>,
) {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string!").into();
    let arraysize: jsize = env.get_array_length(&addresses).expect("Couldn't get Java longarray!");
    let target_pid: i32 = pid.try_into().unwrap();
    let mut addrs: Vec<u64> = vec![0; arraysize as usize];
    let valuestr: String = env.get_string(&value).expect("Couldn't get Java string!").into();

    let elements = env.get_array_elements(&addresses, ReleaseMode::NoCopyBack).unwrap();
    for i in 0..arraysize {
        addrs[i as usize] = elements[i as usize].as_u64();
    }

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => dev,
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return;
        }
    };

    match typ.as_str() {
        "int" => {
            for j in 0..arraysize {
                let value: i32 = valuestr.parse().expect("Failed to parse value as i32");
                let buf = value.to_ne_bytes();
                device.write_mem(target_pid, addrs[j as usize], &buf).unwrap();
            }
        }
        "long" => {
            for j in 0..arraysize {
                let value: i64 = valuestr.parse().expect("Failed to parse value as i64");
                let buf = value.to_ne_bytes();
                device.write_mem(target_pid, addrs[j as usize], &buf).unwrap();
            }
        }
        "float" => {
            for j in 0..arraysize {
                let value: f32 = valuestr.parse().expect("Failed to parse value as f32");
                let buf = value.to_ne_bytes();
                device.write_mem(target_pid, addrs[j as usize], &buf).unwrap();
            }
        }
        "double" => {
            for j in 0..arraysize {
                let value: f64 = valuestr.parse().expect("Failed to parse value as f64");
                let buf = value.to_ne_bytes();
                device.write_mem(target_pid, addrs[j as usize], &buf).unwrap();
            }
        }
        _ => {
            error!("Invalid data type");
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_searchvalues<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    pid: jlong,
    datatype: JString<'a>,
    value1: JString<'a>,
    value2: JString<'a>,
    scantype: jint,
    regions: JString<'a>,
) -> JLongArray<'a> {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string").into();
    let procid: i32 = pid.try_into().unwrap();
    let scantyp: i32 = scantype.try_into().unwrap();
    let tvalue1: String = env.get_string(&value1).expect("Couldn't get Java string").into();
    let tvalue2: String = env.get_string(&value2).expect("Couldn't get Java string").into();

    let regions_str: String = env.get_string(&regions).expect("Couldn't get Java string").into();

    let out = env.new_long_array(0).unwrap();

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return out;
        }
    };

    let m_regions = regions_str.split(',')
        .filter_map(|s| MemoryRegion::from_str(s))
        .collect::<Vec<_>>();

    let mut memory_sections = MemSearchSafeWorkSecWrapper::new();
    memory_sections.load_memory_sections(device.clone(), procid, m_regions).expect("Failed to load memory sections");

    let result: Vec<jlong> = match typ.as_str() {
        "int" => {
            let value1_parsed: i32 = tvalue1.parse().expect("Failed to parse value1 as i32");
            let value2_parsed: i32 = tvalue2.parse().expect("Failed to parse value2 as i32");
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_value::<i32>(
                procid, Arc::new(Mutex::new(memory_sections)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "long" => {
            let value1_parsed: i64 = tvalue1.parse().expect("Failed to parse value1 as i64");
            let value2_parsed: i64 = tvalue2.parse().expect("Failed to parse value2 as i64");
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_value::<i64>(
                procid, Arc::new(Mutex::new(memory_sections)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, 8, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "float" => {
            let value1_parsed: f32 = tvalue1.parse().expect("Failed to parse value1 as f32");
            let value2_parsed: f32 = tvalue2.parse().expect("Failed to parse value2 as f32");
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_value::<f32>(
                procid, Arc::new(Mutex::new(memory_sections)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "double" => {
            let value1_parsed: f64 = tvalue1.parse().expect("Failed to parse value1 as f64");
            let value2_parsed: f64 = tvalue2.parse().expect("Failed to parse value2 as f64");
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_value::<f64>(
                procid, Arc::new(Mutex::new(memory_sections)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, 8, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        _ => {
            error!("Unsupported datatype");
            return out;
        }
    };

    let output = env.new_long_array(result.len() as i32).expect("Couldn't create new JLongArray");
    env.set_long_array_region(&output, 0, &result).expect("Couldn't set JLongArray region");
    output
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_searchgroupvalues<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    pid: jlong,
    datatype: JString<'a>,
    values: JObjectArray<'a>,
    proximity: jlong,
    regions: JString<'a>,
) -> JLongArray<'a> {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string").into();
    let procid: i32 = pid.try_into().unwrap();
    let length = env.get_array_length(&values).unwrap();
    let mut group_values = Vec::with_capacity(length as usize);

    for i in 0..length {
        let obj = env.get_object_array_element(&values, i).unwrap();
        let j_string = JString::from(obj);
        let rust_string: String = env.get_string(&j_string).unwrap().into();
        group_values.push(rust_string);
    }

    let regions_str: String = env.get_string(&regions).expect("Couldn't get Java string").into();

    let out = env.new_long_array(0).unwrap();

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return out;
        }
    };

    let m_regions = regions_str.split(',')
        .filter_map(|s| MemoryRegion::from_str(s))
        .collect::<Vec<_>>();

    let mut memory_sections = MemSearchSafeWorkSecWrapper::new();
    memory_sections.load_memory_sections(device.clone(), procid, m_regions).expect("Failed to load memory sections");

    let prox: usize = proximity.try_into().unwrap();

    let result: Vec<jlong> = match typ.as_str() {
        "int" => {
            let mut values_parsed: Vec<i32> = Vec::with_capacity(group_values.len());
            for i in 0..group_values.len() {
                let value = group_values[i].clone();
                values_parsed.push(value.parse().unwrap());
            }
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_group_values::<i32>(
                procid, Arc::new(Mutex::new(memory_sections)), values_parsed, prox, Some(0.00001f32), 4, size_of::<i32>(), force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "long" => {
            let mut values_parsed: Vec<i64> = Vec::with_capacity(group_values.len());
            for i in 0..group_values.len() {
                let value = group_values[i].clone();
                values_parsed.push(value.parse().unwrap());
            }
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_group_values::<i64>(
                procid, Arc::new(Mutex::new(memory_sections)), values_parsed, prox,  Some(0.00001f32), 4, size_of::<i64>(), force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "float" => {
            let mut values_parsed: Vec<f32> = Vec::with_capacity(group_values.len());
            for i in 0..group_values.len() {
                let value = group_values[i].clone();
                values_parsed.push(value.parse().unwrap());
            }
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_group_values::<f32>(
                procid, Arc::new(Mutex::new(memory_sections)), values_parsed, prox, Some(0.00001f32), 4, size_of::<f32>(), force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "double" => {
            let mut values_parsed: Vec<f64> = Vec::with_capacity(group_values.len());
            for i in 0..group_values.len() {
                let value = group_values[i].clone();
                values_parsed.push(value.parse().unwrap());
            }
            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_group_values::<f64>(
                procid, Arc::new(Mutex::new(memory_sections)), values_parsed, prox, Some(0.00001f32), 4, size_of::<f64>(), force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        _ => {
            error!("Unsupported datatype");
            return out;
        }
    };

    let output = env.new_long_array(result.len() as i32).expect("Couldn't create new JLongArray");
    env.set_long_array_region(&output, 0, &result).expect("Couldn't set JLongArray region");
    output
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_filtervalues<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    pid: jlong,
    datatype: JString<'a>,
    value1: JString<'a>,
    value2: JString<'a>,
    scantype: jint,
    addresses: JLongArray<'a>,
) -> JLongArray<'a> {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string").into();
    let procid: i32 = pid.try_into().unwrap();
    let scantyp: i32 = scantype.try_into().unwrap();
    let tvalue1: String = env.get_string(&value1).expect("Couldn't get Java string").into();
    let tvalue2: String = env.get_string(&value2).expect("Couldn't get Java string").into();

    let addresses_array = env.get_array_elements(&addresses, ReleaseMode::NoCopyBack).unwrap();

    let mut addrs: Vec<u64> = Vec::with_capacity(addresses_array.len());
    for j in 0..addresses_array.len() {
        addrs.push(addresses_array[j].as_u64());
    }

    let out = env.new_long_array(0).unwrap();

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return out;
        }
    };

    let result: Vec<jlong> = match typ.as_str() {
        "int" => {
            let value1_parsed: i32 = tvalue1.parse().expect("Failed to parse value1 as i32");
            let value2_parsed: i32 = tvalue2.parse().expect("Failed to parse value2 as i32");

            let mut ainfo: Vec<AddrResultInfo> = Vec::with_capacity(addrs.len());
            for &addr in &addrs {
                ainfo.push(AddrResultInfo { addr, size: size_of::<i32>() });
            }

            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_addr_next_value::<i32>(
                procid, Arc::new(Mutex::new(ainfo)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "long" => {
            let value1_parsed: i64 = tvalue1.parse().expect("Failed to parse value1 as i64");
            let value2_parsed: i64 = tvalue2.parse().expect("Failed to parse value2 as i64");

            let mut ainfo: Vec<AddrResultInfo> = Vec::with_capacity(addrs.len());
            for &addr in &addrs {
                ainfo.push(AddrResultInfo { addr, size: size_of::<i64>() });
            }

            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_addr_next_value::<i64>(
                procid, Arc::new(Mutex::new(ainfo)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "float" => {
            let value1_parsed: f32 = tvalue1.parse().expect("Failed to parse value1 as f32");
            let value2_parsed: f32 = tvalue2.parse().expect("Failed to parse value2 as f32");

            let mut ainfo: Vec<AddrResultInfo> = Vec::with_capacity(addrs.len());
            for &addr in &addrs {
                ainfo.push(AddrResultInfo { addr, size: size_of::<f32>() });
            }

            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_addr_next_value::<f32>(
                procid, Arc::new(Mutex::new(ainfo)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        "double" => {
            let value1_parsed: f64 = tvalue1.parse().expect("Failed to parse value1 as f64");
            let value2_parsed: f64 = tvalue2.parse().expect("Failed to parse value2 as f64");

            let mut ainfo: Vec<AddrResultInfo> = Vec::with_capacity(addrs.len());
            for &addr in &addrs {
                ainfo.push(AddrResultInfo { addr, size: size_of::<f64>() });
            }

            let force_stop_signal = Arc::new(AtomicBool::new(false));
            let res: Vec<AddrResultInfo> = device.search_addr_next_value::<f64>(
                procid, Arc::new(Mutex::new(ainfo)), value1_parsed, value2_parsed, 0.00001f32, getscantype(scantyp), 4, force_stop_signal
            ).expect("Failed to search value");

            res.into_iter().map(|result| result.addr.try_into().unwrap()).collect()
        }
        _ => {
            error!("Unsupported datatype");
            return out;
        }
    };

    let output = env.new_long_array(result.len() as i32).expect("Couldn't create new JLongArray");
    env.set_long_array_region(&output, 0, &result).expect("Couldn't set JLongArray region");
    output
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_yervant_huntgames_backend_HuntService_filtergroupvalues<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    pid: jlong,
    datatype: JString<'a>,
    values: JObjectArray<'a>,
    addresses: JLongArray<'a>,
) -> JLongArray<'a> {
    let typ: String = env.get_string(&datatype).expect("Couldn't get Java string").into();
    let procid: i32 = pid.try_into().unwrap();

    let addresses_array = env.get_array_elements(&addresses, ReleaseMode::NoCopyBack).unwrap();

    let mut addrs: Vec<u64> = Vec::with_capacity(addresses_array.len());
    for j in 0..addresses_array.len() {
        addrs.push(addresses_array[j].as_u64());
    }

    let out = env.new_long_array(0).unwrap();

    let device = match Device::new(DEFAULT_DRIVER_PATH) {
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            error!("Failed to open device: {:?}", e);
            return out;
        }
    };

    let length = env.get_array_length(&values).unwrap();
    let mut group_values = Vec::with_capacity(length as usize);

    for i in 0..length {
        let obj = env.get_object_array_element(&values, i).unwrap();
        let j_string = JString::from(obj);
        let rust_string: String = env.get_string(&j_string).unwrap().into();
        group_values.push(rust_string);
    }

    let result: Vec<jlong> = match typ.as_str() {
        "int" => {
            let mut values_parsed: Vec<i32> = Vec::with_capacity(group_values.len());
            let mut res: Vec<jlong> = Vec::new();

            for value in group_values {
                match value.parse::<i32>() {
                    Ok(parsed_value) => values_parsed.push(parsed_value),
                    Err(e) => error!("Error converting value '{}': {:?}", value, e),
                }
            }

            for &addr in &addrs {
                let mut buf = vec![0u8; 4];
                if let Ok(_) = device.read_mem(procid, addr, &mut buf) {
                    let value = i32::from_ne_bytes(buf.try_into().unwrap());
                    if values_parsed.contains(&value) {
                        res.push(addr as jlong);
                    }
                } else {
                    error!("Error reading memory in: {}", addr);
                }
            }

            res
        }
        "long" => {
            let mut values_parsed: Vec<i64> = Vec::with_capacity(group_values.len());
            let mut res: Vec<jlong> = Vec::new();

            for value in group_values {
                match value.parse::<i64>() {
                    Ok(parsed_value) => values_parsed.push(parsed_value),
                    Err(e) => error!("Error converting value '{}': {:?}", value, e),
                }
            }

            for &addr in &addrs {
                let mut buf = vec![0u8; 8];
                if let Ok(_) = device.read_mem(procid, addr, &mut buf) {
                    let value = i64::from_ne_bytes(buf.try_into().unwrap());
                    if values_parsed.contains(&value) {
                        res.push(addr as jlong);
                    }
                } else {
                    error!("Error reading memory in: {}", addr);
                }
            }

            res
        }
        "float" => {
            let mut values_parsed: Vec<f32> = Vec::with_capacity(group_values.len());
            let mut res: Vec<jlong> = Vec::new();
            let error_margin: f32 = 0.0001;

            for value in group_values {
                match value.parse::<f32>() {
                    Ok(parsed_value) => values_parsed.push(parsed_value),
                    Err(e) => error!("Error converting value '{}': {:?}", value, e),
                }
            }

            for &addr in &addrs {
                let mut buf = vec![0u8; 4];
                if let Ok(_) = device.read_mem(procid, addr, &mut buf) {
                    let value = f32::from_ne_bytes(buf.try_into().unwrap());

                    if values_parsed.iter().any(|&v| (v - value).abs() <= error_margin) {
                        res.push(addr as jlong);
                    }
                } else {
                    error!("Error reading memory in: {}", addr);
                }
            }

            res
        },
        "double" => {
            let mut values_parsed: Vec<f64> = Vec::with_capacity(group_values.len());
            let mut res: Vec<jlong> = Vec::new();
            let error_margin: f64 = 0.0001;

            for value in group_values {
                match value.parse::<f64>() {
                    Ok(parsed_value) => values_parsed.push(parsed_value),
                    Err(e) => eprintln!("Error converting value '{}': {:?}", value, e),
                }
            }

            for &addr in &addrs {
                let mut buf = vec![0u8; 8];
                if let Ok(_) = device.read_mem(procid, addr, &mut buf) {
                    let value = f64::from_ne_bytes(buf.try_into().unwrap());

                    if values_parsed.iter().any(|&v| (v - value).abs() <= error_margin) {
                        res.push(addr as jlong);
                    }
                } else {
                    eprintln!("Error reading memory in: {}", addr);
                }
            }

            res
        }
        _ => {
            error!("Unsupported datatype");
            return out;
        }
    };

    let output = env.new_long_array(result.len() as i32).expect("Couldn't create new JLongArray");
    env.set_long_array_region(&output, 0, &result).expect("Couldn't set JLongArray region");
    output
}