# Security Policy

Please report suspected memory-safety bugs, privilege-boundary errors, or
resource-exhaustion vulnerabilities privately to `hi@tychen.cc`. Include the
affected package/version, a minimal reproducer if safe to share, and the
expected versus observed security boundary.

The latest released 0.x minor line receives security fixes. Older incompatible
minor lines may be fixed when practical, but are not promised long-term
support. Affected releases are yanked only when they are unsound, cannot be
built, or cannot be repaired safely through a compatible patch.
