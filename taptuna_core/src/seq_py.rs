use pyo3::prelude::*;
use crate::seq::{SeqTracker, Segment, sort_segments, SEQ_WINDOW};

/// Create Python module for seq tracking
pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "seq")?;
    
    m.add_class::<PySeqTracker>()?;
    m.add_class::<PySegment>()?;
    m.add_function(wrap_pyfunction!(sort_segments_py, &m)?)?;
    
    Ok(m)
}

#[pyclass]
struct PySeqTracker {
    inner: SeqTracker,
}

#[pymethods]
impl PySeqTracker {
    #[new]
    #[pyo3(signature = (syn_seq=None))]
    fn new(syn_seq: Option<u32>) -> Self {
        PySeqTracker {
            inner: SeqTracker::new(syn_seq),
        }
    }
    
    #[getter]
    fn reference(&self) -> u32 {
        self.inner.reference()
    }
    
    #[getter]
    fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
    
    #[getter]
    fn isn(&self) -> Option<u32> {
        self.inner.isn()
    }
    
    fn seq_to_offset(&self, abs_seq: u32) -> Option<u64> {
        self.inner.seq_to_offset(abs_seq)
    }
    
    fn try_advance(&mut self, new_contiguous_seq: u32) -> bool {
        self.inner.try_advance(new_contiguous_seq)
    }
    
    fn in_window(&self, seq: u32) -> bool {
        self.inner.in_window(seq)
    }
    
    fn offset_to_seq(&self, offset: u64) -> Option<u32> {
        self.inner.offset_to_seq(offset)
    }
}

#[pyclass]
#[derive(Clone)]
struct PySegment {
    #[pyo3(get, set)]
    abs_seq: u32,
    #[pyo3(get, set)]
    len: usize,
    #[pyo3(get, set)]
    frame_number: u32,
    #[pyo3(get, set)]
    is_retransmission: bool,
    #[pyo3(get, set)]
    has_conflict: bool,
    #[pyo3(get, set)]
    data: Vec<u8>,
}

#[pymethods]
impl PySegment {
    #[new]
    fn new(abs_seq: u32, len: usize, frame_number: u32, data: Vec<u8>) -> Self {
        PySegment {
            abs_seq,
            len,
            frame_number,
            is_retransmission: false,
            has_conflict: false,
            data,
        }
    }
    
    fn end_seq(&self) -> u32 {
        self.abs_seq.wrapping_add(self.len as u32)
    }
    
    fn overlaps(&self, other: &PySegment) -> bool {
        let self_end = self.end_seq();
        let other_end = other.end_seq();
        
        let self_before_other = self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW;
        let other_before_self = other_end.wrapping_sub(self.abs_seq) > SEQ_WINDOW;
        
        !(self_before_other || other_before_self)
    }
    
    fn is_before(&self, other: &PySegment) -> bool {
        let self_end = self.end_seq();
        self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW
    }
}

#[pyfunction]
fn sort_segments_py(segments: Vec<PySegment>) -> Vec<PySegment> {
    let mut rust_segments: Vec<Segment> = segments.iter().map(|s| Segment {
        abs_seq: s.abs_seq,
        len: s.len,
        frame_number: s.frame_number,
        is_retransmission: s.is_retransmission,
        has_conflict: s.has_conflict,
        data: s.data.clone(),
    }).collect();
    
    sort_segments(&mut rust_segments);
    
    rust_segments.into_iter().map(|s| PySegment {
        abs_seq: s.abs_seq,
        len: s.len,
        frame_number: s.frame_number,
        is_retransmission: s.is_retransmission,
        has_conflict: s.has_conflict,
        data: s.data,
    }).collect()
}