/**
 * Reads a browser `File` as text via `FileReader` (decision №10 of
 * docs/source/snapshots.md fork h.5 — snapshot import is file-only, no
 * textarea, and no separate multipart endpoint: the text is parsed as JSON by
 * the caller and sent as a normal JSON request body).
 */
export function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("Could not read the file"));
    reader.readAsText(file);
  });
}
