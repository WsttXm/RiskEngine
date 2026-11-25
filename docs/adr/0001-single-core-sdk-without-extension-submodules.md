# Single Core SDK Without Optional Extension Submodules

Status: accepted

Before releasing v2.0.0, we removed the five optional extension submodules (`:riskengine-appzygote`, `:riskengine-ktx`, `:riskengine-play-integrity`, `:riskengine-soter-ext`, and `:riskengine-experimental`) along with their orphan SPIs and build/CI hooks in `:riskengine-sdk`, keeping only `:riskengine-sdk`, `:demo`, and `:integration-test`.

## Considered Options

- **Keep all five extension submodules as separately published Maven artifacts**: Preserves optional Kotlin DSL, Play Integrity, SOTER, AppZygote, and experimental diagnostics, but commits the project to maintaining six public ABIs, extra native libraries, multi-module release automation, and permanent SPI surface inside `:riskengine-sdk`.
- **Keep core SPI hooks as dormant extension points while deleting the modules**: Leaves untested, zero-consumer public interfaces (`AppZygoteSelinuxProvider`, `NativeServiceMountProvider`, `enableAppZygoteProbe`) baked into v2.0.0 ABI.
- **Consolidate around a single zero-dependency core SDK (chosen)**: Focuses maintenance, verification, and binary-compatibility guarantees on one self-contained `:riskengine-sdk` AAR plus `:demo` and `:integration-test`, avoiding dead SPI surface before v2.0.0 locks public compatibility.

## Consequences

- `:riskengine-sdk` carries zero orphan SPIs or unused configuration flags (`enableAppZygoteProbe` removed before v2.0.0 release).
- CI and release pipelines verify and ship only the core `:riskengine-sdk` AAR, `:demo` APK, and `:integration-test` instrumentation suite.
- Any future optional ecosystem integrations will be introduced only when there is a concrete production consumer and dedicated release contract.
