// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Style", "IDE0054:Use compound assignment", Justification = "NIST does not use compound assignment notation, so neither do we.")]
[assembly: SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "We use the naming convention of NIST, even if it violates the C# convention.")]
