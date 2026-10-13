use pyo3::prelude::*;

/// Returns the version of the native core.
#[pyfunction]
fn __version__() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Python module definition for `taptuna._native`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(__version__, m)?)?;
    Ok(())
}