use pyo3::prelude::*;
use pyo3::create_exception;
use crate::wire::{ParsedPacket, WireParseError as RustWireParseError, EtherType, IpProtocol};

create_exception!(wire, WireParseError, pyo3::exceptions::PyException);

/// Create Python module for wire parsing
pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "wire")?;
    
    // Add ParsedPacket class
    m.add_class::<PyParsedPacket>()?;
    
    // Add parse function
    m.add_function(wrap_pyfunction!(parse_packet, &m)?)?;
    
    // Add WireParseError exception
    m.add("WireParseError", py.get_type_bound::<WireParseError>())?;
    
    // Add EtherType enum
    m.add_class::<PyEtherType>()?;
    
    // Add IpProtocol enum
    m.add_class::<PyIpProtocol>()?;
    
    Ok(m)
}

#[pyclass]
#[derive(Clone)]
struct PyParsedPacket {
    inner: ParsedPacket,
}

#[pymethods]
impl PyParsedPacket {
    #[getter]
    fn frame_number(&self) -> u32 {
        self.inner.frame_number
    }
    
    #[getter]
    fn timestamp(&self) -> f64 {
        self.inner.timestamp
    }
    
    #[getter]
    fn src_mac(&self) -> String {
        self.inner.src_mac.to_string()
    }
    
    #[getter]
    fn dst_mac(&self) -> String {
        self.inner.dst_mac.to_string()
    }
    
    #[getter]
    fn ethertype(&self) -> PyEtherType {
        PyEtherType(self.inner.ethertype)
    }
    
    #[getter]
    fn vlan_tci(&self) -> Option<u16> {
        self.inner.vlan_tci
    }
    
    #[getter]
    fn ip_version(&self) -> u8 {
        self.inner.ip_version
    }
    
    #[getter]
    fn ip_ihl(&self) -> u8 {
        self.inner.ip_ihl
    }
    
    #[getter]
    fn ip_tos(&self) -> u8 {
        self.inner.ip_tos
    }
    
    #[getter]
    fn ip_total_len(&self) -> u16 {
        self.inner.ip_total_len
    }
    
    #[getter]
    fn ip_id(&self) -> u16 {
        self.inner.ip_id
    }
    
    #[getter]
    fn ip_flags(&self) -> u8 {
        self.inner.ip_flags
    }
    
    #[getter]
    fn ip_frag_offset(&self) -> u16 {
        self.inner.ip_frag_offset
    }
    
    #[getter]
    fn ip_ttl(&self) -> u8 {
        self.inner.ip_ttl
    }
    
    #[getter]
    fn ip_protocol(&self) -> PyIpProtocol {
        PyIpProtocol(self.inner.ip_protocol)
    }
    
    #[getter]
    fn ip_checksum(&self) -> u16 {
        self.inner.ip_checksum
    }
    
    #[getter]
    fn ip_src(&self) -> String {
        self.inner.ip_src.to_string()
    }
    
    #[getter]
    fn ip_dst(&self) -> String {
        self.inner.ip_dst.to_string()
    }
    
    #[getter]
    fn tcp_src_port(&self) -> u16 {
        self.inner.tcp_src_port
    }
    
    #[getter]
    fn tcp_dst_port(&self) -> u16 {
        self.inner.tcp_dst_port
    }
    
    #[getter]
    fn tcp_seq(&self) -> u32 {
        self.inner.tcp_seq
    }
    
    #[getter]
    fn tcp_ack(&self) -> u32 {
        self.inner.tcp_ack
    }
    
    #[getter]
    fn tcp_data_offset(&self) -> u8 {
        self.inner.tcp_data_offset
    }
    
    #[getter]
    fn tcp_flags(&self) -> u8 {
        self.inner.tcp_flags
    }
    
    #[getter]
    fn tcp_window(&self) -> u16 {
        self.inner.tcp_window
    }
    
    #[getter]
    fn tcp_checksum(&self) -> u16 {
        self.inner.tcp_checksum
    }
    
    #[getter]
    fn tcp_urgent_ptr(&self) -> u16 {
        self.inner.tcp_urgent_ptr
    }
    
    #[getter]
    fn payload(&self) -> Vec<u8> {
        self.inner.payload.clone()
    }
    
    #[getter]
    fn payload_sha256(&self) -> Vec<u8> {
        self.inner.payload_sha256.to_vec()
    }
    
    #[getter]
    fn tcp_flags_syn(&self) -> bool {
        (self.inner.tcp_flags & 0x02) != 0
    }
    
    #[getter]
    fn tcp_flags_ack(&self) -> bool {
        (self.inner.tcp_flags & 0x10) != 0
    }
    
    #[getter]
    fn tcp_flags_fin(&self) -> bool {
        (self.inner.tcp_flags & 0x01) != 0
    }
    
    #[getter]
    fn tcp_flags_rst(&self) -> bool {
        (self.inner.tcp_flags & 0x04) != 0
    }
    
    #[getter]
    fn tcp_len(&self) -> usize {
        self.inner.payload.len()
    }
}

#[pyclass]
#[derive(Clone, Copy)]
struct PyEtherType(EtherType);

#[pymethods]
impl PyEtherType {
    #[getter]
    fn value(&self) -> u16 {
        self.0 as u16
    }
    
    #[getter]
    fn name(&self) -> &'static str {
        match self.0 {
            EtherType::IPv4 => "IPv4",
            EtherType::VLAN8021Q => "VLAN_802_1Q",
            EtherType::VLAN8021AD => "VLAN_802_1AD",
        }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
struct PyIpProtocol(IpProtocol);

#[pymethods]
impl PyIpProtocol {
    #[getter]
    fn value(&self) -> u8 {
        self.0 as u8
    }
    
    #[getter]
    fn name(&self) -> &'static str {
        "TCP"
    }
}

#[pyfunction]
fn parse_packet(frame_number: u32, timestamp: f64, data: &[u8]) -> PyResult<Option<PyParsedPacket>> {
    match ParsedPacket::parse(frame_number, timestamp, data) {
        Ok(Some(pkt)) => Ok(Some(PyParsedPacket { inner: pkt })),
        Ok(None) => Ok(None),
        Err(e) => Err(WireParseError::new_err(e.to_string())),
    }
}