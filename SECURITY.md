# Security Policy

RansomLeak Pro processes untrusted archive metadata and limited nested archive content. The project applies explicit recursion, entry-count, size, and compression-ratio limits, but archive parsing libraries still execute in the application process.

Only analyze datasets you are authorized to inspect. For hostile or unknown samples, use an isolated workstation or sandboxed environment.

Please report security issues privately to the repository owner rather than publishing exploit details in a public issue before a fix is available.
