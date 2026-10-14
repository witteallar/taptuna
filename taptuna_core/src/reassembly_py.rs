use pyo3::prelude::*;
use pyo3::types::PyType;
use crate::reassembly::{ReassembledStream, ReassemblyInput, OverlapPolicy, Gap, Ambiguity, StreamSegmentInfo, SegmentStatus};

/// Create Python module for reassembly
pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "reassembly")?;
    
    m.add_class::<PyReassemblyInput>()?;
    m.add_class::<PySegmentWrapper>()?;
    m.add_class::<PyOverlapPolicy>()?;
    m.add_class::<PyReassembledStream>()?;
    m.add_class::<PyGap>()?;
    m.add_class::<PyAmbiguity>()?;
    m.add_class::<PyStreamSegmentInfo>()?;
    m.add_class::<PySegmentStatus>()?;
    m.add_function(wrap_pyfunction!(reassemble_py, &m)?)?;
    
    Ok(m)
}

#[pyclass]
#[derive(Clone)]
struct PyReassemblyInput {
    segments: Vec<PySegmentWrapper>,
    syn_seq: Option<u32>,
    overlap_policy: OverlapPolicy,
}

#[pyclass]
#[derive(Clone)]
struct PySegmentWrapper {
    #[pyo3(get, set)]
    abs_seq: u32,
    #[pyo3(get, set)]
    len: usize,
    #[pyo3(get, set)]
    frame_number: u32,
    #[pyo3(get, set)]
    data: Vec<u8>,
}

#[pymethods]
impl PyReassemblyInput {
    #[new]
    #[pyo3(signature = (segments, overlap_policy, syn_seq=None))]
    fn new(segments: Vec<PySegmentWrapper>, overlap_policy: PyOverlapPolicy, syn_seq: Option<u32>) -> Self {
        PyReassemblyInput {
            segments,
            syn_seq,
            overlap_policy: overlap_policy.0,
        }
    }
}

#[pymethods]
impl PySegmentWrapper {
    #[new]
    fn new(abs_seq: u32, len: usize, frame_number: u32, data: Vec<u8>) -> Self {
        PySegmentWrapper {
            abs_seq,
            len,
            frame_number,
            data,
        }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
struct PyOverlapPolicy(OverlapPolicy);

#[pymethods]
impl PyOverlapPolicy {
    #[classmethod]
    fn first_wins(_cls: &Bound<'_, PyType>) -> Self {
        PyOverlapPolicy(OverlapPolicy::FirstWins)
    }
    
    #[classmethod]
    fn last_wins(_cls: &Bound<'_, PyType>) -> Self {
        PyOverlapPolicy(OverlapPolicy::LastWins)
    }
    
    #[classmethod]
    fn halt_and_mark(_cls: &Bound<'_, PyType>) -> Self {
        PyOverlapPolicy(OverlapPolicy::HaltAndMark)
    }
    
    #[staticmethod]
    fn from_str(s: &str) -> Option<Self> {
        OverlapPolicy::from_str(s).map(PyOverlapPolicy)
    }
    
    #[getter]
    fn name(&self) -> &'static str {
        match self.0 {
            OverlapPolicy::FirstWins => "first_wins",
            OverlapPolicy::LastWins => "last_wins",
            OverlapPolicy::HaltAndMark => "halt_and_mark",
        }
    }
}

#[pyclass]
struct PyReassembledStream {
    inner: ReassembledStream,
}

#[pymethods]
impl PyReassembledStream {
    #[getter]
    fn data(&self) -> Vec<u8> {
        self.inner.data.clone()
    }
    
    #[getter]
    fn gaps(&self) -> Vec<PyGap> {
        self.inner.gaps.iter().cloned().map(|g| PyGap { inner: g }).collect()
    }
    
    #[getter]
    fn ambiguities(&self) -> Vec<PyAmbiguity> {
        self.inner.ambiguities.iter().cloned().map(|a| PyAmbiguity { inner: a }).collect()
    }
    
    #[getter]
    fn total_bytes(&self) -> u64 {
        self.inner.total_bytes
    }
    
    #[getter]
    fn stream_start_abs_seq(&self) -> u32 {
        self.inner.stream_start_abs_seq
    }
    
    #[getter]
    fn roles_established(&self) -> bool {
        self.inner.roles_established
    }
    
    #[getter]
    fn segments(&self) -> Vec<PyStreamSegmentInfo> {
        self.inner.segments.iter().cloned().map(|s| PyStreamSegmentInfo { inner: s }).collect()
    }
}

#[pyclass]
#[derive(Clone)]
struct PyGap {
    inner: Gap,
}

#[pymethods]
impl PyGap {
    #[getter]
    fn offset(&self) -> u64 {
        self.inner.offset
    }
    
    #[getter]
    fn length(&self) -> u64 {
        self.inner.length
    }
    
    #[getter]
    fn frames(&self) -> Vec<u32> {
        self.inner.frames.clone()
    }
}

#[pyclass]
#[derive(Clone)]
struct PyAmbiguity {
    inner: Ambiguity,
}

#[pymethods]
impl PyAmbiguity {
    #[getter]
    fn offset(&self) -> u64 {
        self.inner.offset
    }
    
    #[getter]
    fn length(&self) -> u64 {
        self.inner.length
    }
    
    #[getter]
    fn frames(&self) -> Vec<u32> {
        self.inner.frames.clone()
    }
    
    #[getter]
    fn policy(&self) -> PyOverlapPolicy {
        PyOverlapPolicy(self.inner.policy)
    }
}

#[pyclass]
#[derive(Clone)]
struct PyStreamSegmentInfo {
    inner: StreamSegmentInfo,
}

#[pymethods]
impl PyStreamSegmentInfo {
    #[getter]
    fn stream_offset(&self) -> u64 {
        self.inner.stream_offset
    }
    
    #[getter]
    fn length(&self) -> usize {
        self.inner.length
    }
    
    #[getter]
    fn abs_seq_start(&self) -> u32 {
        self.inner.abs_seq_start
    }
    
    #[getter]
    fn abs_seq_end(&self) -> u32 {
        self.inner.abs_seq_end
    }
    
    #[getter]
    fn status(&self) -> PySegmentStatus {
        PySegmentStatus(self.inner.status)
    }
    
    #[getter]
    fn first_frame(&self) -> u32 {
        self.inner.first_frame
    }
    
    #[getter]
    fn last_frame(&self) -> u32 {
        self.inner.last_frame
    }
}

#[pyclass]
#[derive(Clone, Copy)]
struct PySegmentStatus(SegmentStatus);

#[pymethods]
impl PySegmentStatus {
    #[getter]
    fn name(&self) -> &'static str {
        match self.0 {
            SegmentStatus::Clean => "clean",
            SegmentStatus::Overlap => "overlap",
            SegmentStatus::GapBefore => "gap_before",
        }
    }
}

#[pyfunction]
fn reassemble_py(input: &PyReassemblyInput) -> PyResult<PyReassembledStream> {
    // Convert Python segments to Rust segments
    use crate::seq::Segment;
    
    let rust_segments: Vec<Segment> = input.segments.iter().map(|s| {
        Segment::new(s.abs_seq, s.len, s.frame_number, s.data.clone())
    }).collect();
    
    let rust_input = ReassemblyInput::new(rust_segments, input.syn_seq, input.overlap_policy);
    let result = crate::reassembly::reassemble(rust_input);
    
    Ok(PyReassembledStream { inner: result })
}