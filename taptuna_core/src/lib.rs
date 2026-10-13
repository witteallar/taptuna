use pyo3::prelude::*;

mod wire;
mod seq;
mod reassembly;
mod wire_py;
mod seq_py;
mod reassembly_py;

/// Returns the version of the native core.
#[pyfunction]
fn __version__() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Python module definition for `taptuna._native`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(__version__, m)?)?;
    // Re-export submodules
    m.add("wire", wire_py::create_module(m.py())?)?;
    m.add("seq", seq_py::create_module(m.py())?)?;
    m.add("reassembly", reassembly_py::create_module(m.py())?)?;
    Ok(())
}