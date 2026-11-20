export function platformOf(name) {
  return { windows: name === "win32", fold: name === "win32" || name === "darwin" };
}

// Resolves `text` against `base` (already resolved) into an absolute, `/`-separated path,
// lower-cased where the file system folds case, so resolved paths compare as strings.
export function resolvePath(text, base, platform) {
  const path = platform.windows ? text.replaceAll("\\", "/").replace(/^\/([a-zA-Z])(?=\/|$)/, "$1:") : text;
  const absolute = path.startsWith("/") || (platform.windows && /^[a-zA-Z]:(\/|$)/.test(path));
  const [root, ...parts] = (absolute ? path : `${base}/${path}`).split("/");
  const kept = [];
  for (const part of parts) {
    if (part === "..") kept.pop();
    else if (part !== "" && part !== ".") kept.push(part);
  }
  return foldPath(`${root}/${kept.join("/")}`, platform);
}

export function foldPath(path, platform) {
  return platform.fold ? path.toLowerCase() : path;
}

export function isWithin(path, dir) {
  return path === dir || path.startsWith(dir.endsWith("/") ? dir : `${dir}/`);
}

export function joinPath(dir, rel) {
  if (rel === "") return dir;
  return `${dir.endsWith("/") ? dir : `${dir}/`}${rel}`;
}

// The innermost checkout root holding `path`, and `path` relative to it; null outside the repository.
export function locate(path, roots) {
  const root = roots.filter((candidate) => isWithin(path, candidate)).reduce((a, b) => (b.length > a.length ? b : a), "");
  if (root === "") return null;
  const rel = path === root ? "" : path.slice(root.endsWith("/") ? root.length : root.length + 1);
  return { root, rel };
}
