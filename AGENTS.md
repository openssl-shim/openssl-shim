# AGENTS.md

## Purpose

This document is a **policy** for future agents working in this repository.
It is intentionally prescriptive: follow these rules unless explicitly told otherwise.

---

## 1) Compatibility contract

- Target OpenSSL **3.x semantics**.
- Do not add legacy-only compatibility behavior unless a current in-repo consumer requires it.
- Keep `find_package(OpenSSL ...)` behavior consistent with this contract.
- Backwards compatibility is not necessary. No need to create compatibility shims or fallbacks.

---

## 2) Project structure (ownership)

Use these boundaries when adding/changing functionality:

- `include/openssl/*.h`
  - Public shim API surface (declarations/macros visible to consumers).
- `src/tls_common.hpp`
  - Shared internal types and helper declarations used by multiple translation units.
- `src/tls_common.cpp`
  - Backend-agnostic implementations and cross-backend shared behavior.
- `src/tls_shared_exports.inl`
  - Shared exported C-API wrapper bodies that must compile in backend TU context.
- `src/tls_mbedtls.cpp`, `src/tls_schannel.cpp`, `src/tls_apple.cpp`
  - Backend-specific logic only.

If code is not backend-specific, it should not be copy-pasted into multiple backend files.

---

## 3) Anti-duplication rules (MUST)

When introducing new API/symbol behavior:

1. **Implement once** in shared location if feasible.
2. Only keep code in backend files when it is genuinely backend/OS-specific.
3. If identical wrappers are needed in multiple backend TUs, place shared body in `tls_shared_exports.inl`.
4. Shared C++ utility logic should live under `native_tls::...` (declared in `tls_internal.hpp`, implemented in `tls_backend.cpp`) unless there is a strong reason otherwise.

Before committing, quickly scan for new duplication across backend files.

---

## 4) Test and dependency policy

- For multi-process/runtime tests, use Python runners.
- Pass explicit binary paths from CMake (`$<TARGET_FILE:...>`); no path guessing/fallback logic.
- Use explicit timeout values in runners and CTest.
- In test/subproject integration, let dependencies resolve OpenSSL via `find_package(OpenSSL)` through shim logic.
- Do not hardcode fake `OPENSSL_*` found-state variables as a replacement for discovery.

---

## 5) Change workflow (required)

For non-trivial changes:

1. Make the smallest coherent refactor.
2. Build + run relevant tests.
3. Run both backend matrices before finalizing changes.
4. If behavior changed, verify runtime HTTPS tests still pass.

Do not batch unrelated structural changes without intermediate validation.

---

## 6) Review checklist for agents

Before final response, verify:

- [ ] No new cross-backend copy-paste was introduced.
- [ ] Backend-specific code remains in backend files.
- [ ] Shared helpers/symbols are in shared locations.
- [ ] Build/tests pass for required matrices.

If any item fails, fix before handing off.
