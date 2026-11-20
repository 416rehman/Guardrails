const WORD_BREAKS = " \t\r<";
const SEGMENT_BREAKS = "\n;)";
const GLOB_CHARS = "*?[";
const FD_WORD = /^(\d+|\*)$/;

// Splits a Bash or PowerShell command into segments of words after quote removal. The contents
// of `$( )`, backticks and `( )` become segments of their own. Each segment is
// `{ words: [{ text, glob }], redirects: [{ text, glob }] }`; `glob` marks an unquoted wildcard.
export function parseShell(text, dialect) {
  const escape = dialect === "powershell" ? "`" : "\\";
  const segments = [];
  let index = 0;

  const readGroup = (closer) => {
    let segment = { words: [], redirects: [] };
    let word = null;
    let redirectNext = false;
    const append = (chars, glob) => {
      word ??= { text: "", glob: false };
      word.text += chars;
      word.glob ||= glob;
    };
    const endWord = () => {
      if (word === null) return;
      (redirectNext ? segment.redirects : segment.words).push(word);
      redirectNext = false;
      word = null;
    };
    const endSegment = () => {
      endWord();
      if (segment.words.length > 0 || segment.redirects.length > 0) segments.push(segment);
      segment = { words: [], redirects: [] };
    };
    const opensSubstitution = (ch) => {
      if (ch === "$" && text[index] === "(") {
        index += 1;
        readGroup(")");
        return true;
      }
      if (dialect === "bash" && ch === "`") {
        readGroup("`");
        return true;
      }
      return false;
    };
    const readDoubleQuoted = () => {
      append("", false);
      while (index < text.length) {
        const ch = text[index];
        index += 1;
        if (ch === '"') return;
        if (opensSubstitution(ch)) continue;
        const escapes = dialect === "powershell" || '$`"\\\n'.includes(text[index] ?? "");
        if (ch === escape && escapes && index < text.length) {
          append(text[index], false);
          index += 1;
        } else append(ch, false);
      }
    };
    const readRedirect = (ch) => {
      if (word && FD_WORD.test(word.text)) word = null;
      endWord();
      if (ch === "&") index += 1;
      if (text[index] === ">" || text[index] === "|") index += 1;
      if (text[index] === "&" && /[\d-]/.test(text[index + 1] ?? "")) {
        index += 2;
        return;
      }
      if (text[index] === "&") index += 1;
      redirectNext = true;
    };

    while (index < text.length) {
      const ch = text[index];
      const next = text[index + 1];
      index += 1;
      if (ch === closer) return endSegment();
      if (ch === escape) {
        if (next !== "\n" && next !== undefined) append(next, false);
        index += 1;
      } else if (ch === "'") {
        const end = text.indexOf("'", index);
        const stop = end === -1 ? text.length : end;
        append(text.slice(index, stop), false);
        index = stop + 1;
      } else if (ch === '"') readDoubleQuoted();
      else if (opensSubstitution(ch)) continue;
      else if (ch === "(") {
        endWord();
        readGroup(")");
      } else if (ch === ">" || (ch === "&" && next === ">")) readRedirect(ch);
      else if (ch === "|" || ch === "&") {
        if (next === ch) index += 1;
        endSegment();
      } else if (SEGMENT_BREAKS.includes(ch)) endSegment();
      else if (WORD_BREAKS.includes(ch)) endWord();
      else append(ch, GLOB_CHARS.includes(ch));
    }
    return endSegment();
  };

  readGroup(null);
  return segments;
}
