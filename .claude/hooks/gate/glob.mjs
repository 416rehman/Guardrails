const compiled = new Map();

export function matchGlob(glob, path, fold) {
  return matchFrom(glob.split("/"), path.split("/"), fold ? "i" : "");
}

export function literalPrefix(glob) {
  const segments = glob.split("/");
  const firstWild = segments.findIndex((segment) => segment.includes("*") || segment.includes("?"));
  return (firstWild === -1 ? segments : segments.slice(0, firstWild)).join("/");
}

function matchFrom(globs, parts, flags) {
  if (globs.length === 0) return parts.length === 0;
  const [head, ...rest] = globs;
  if (head === "**") {
    for (let skip = 0; skip <= parts.length; skip += 1) {
      if (matchFrom(rest, parts.slice(skip), flags)) return true;
    }
    return false;
  }
  return parts.length > 0 && segmentPattern(head, flags).test(parts[0]) && matchFrom(rest, parts.slice(1), flags);
}

function segmentPattern(segment, flags) {
  const key = `${flags}/${segment}`;
  if (!compiled.has(key)) {
    const source = segment.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*").replaceAll("?", ".");
    compiled.set(key, new RegExp(`^${source}$`, flags));
  }
  return compiled.get(key);
}
