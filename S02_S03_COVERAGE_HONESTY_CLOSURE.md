# S-02 / S-03 closure

`CapabilityId` is now a typed core enum with one canonical `ALL` set. Coverage rows store
`CapabilityId`, not arbitrary strings. `NpmPrimitive::capability_id()` is exhaustive, so a new
primitive variant without a mapping fails compilation.

Universal tests now enforce catalogue uniqueness/completeness, runtime/status honesty for every row,
telemetry consistency for every blocked row, typed primitive registration, and equality between the
canonical typed product-honesty set and the returned report set.

Canonical machine identifier:

```text
ARCHITECTURE_SPECIFIC_ARTIFACT_SELECTION
```

is derived from `CapabilityId::ArchitectureSpecificArtifactSelection` everywhere. The former
stringly-typed catalogue drift is closed without a core-to-scanner dependency cycle.
