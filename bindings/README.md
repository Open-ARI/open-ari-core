# Language bindings

Status: C ABI prototype only. No language packages are published.

The native library target is `openari_ffi`: `libopenari_ffi.so` on Linux,
`libopenari_ffi.dylib` on macOS, and `openari_ffi.dll` on Windows. This keeps
library artifacts and debug symbols distinct from the `openari` executable.
The C header and exported `openari_*` symbols retain their names.

The C header is `include/openari.h`. It exposes ABI version 1 and a JSON report
function with an explicit schema version. The caller supplies all buffers, so
no cross-runtime allocator/free pairing is required. A sizing call returns the
required bytes; output is UTF-8 without a terminating NUL. No pointers are retained.
The current sizing call repeats evaluation; future expensive verification should
use an opaque result handle with explicit destruction rather than verifying twice.

An FFI OK code means a report was written. It never means authenticity was
verified. Validate ABI and report versions, then evaluate the decision and policy.
Unknown enums fail closed. Catching Rust unwinds does not validate caller pointers.

| SDK | Intended implementation | Packaging questions |
| --- | --- | --- |
| Rust | Direct typed core API | Stabilize public types after real profile experience |
| Python | CFFI over shared ABI initially | Bundle native library in platform wheels; benchmark calls and batching |
| Go | CGo over shared ABI | Static vs dynamic distribution; cross-compilation and deployment docs |
| .NET | P/Invoke with safe ownership wrappers | RID-specific native assets and installed NuGet tests |
| Java/Kotlin | FFM on a documented JDK baseline; JNI if older runtimes are required | Native classifier artifacts and tested minimum JDK |

All SDKs share report schema, corpus revision, error semantics, and engine policy.
They do not download a latest binary while importing or accepting a request.
Pin and verify native artifacts during packaging. Offer inspect separately from
verify and mark all forensic values untrusted until verification establishes them.
