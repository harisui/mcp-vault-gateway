/** Case-insensitive glob match supporting `*` (any run) and `?` (one char). */
export function globToRegExp(pattern: string): RegExp {
  const body = pattern
    .trim()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${body}$`, "i");
}

export function matchesAny(name: string, patterns: readonly string[]): string | undefined {
  return patterns.find((p) => p.trim() !== "" && globToRegExp(p).test(name));
}

/** Split a comma-separated pattern list (as stored in 1Password `blocked_tools`). */
export function splitPatterns(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
