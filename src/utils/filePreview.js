export function getPreviewType(mime) {
  if (!mime) return "unknown";

  if (mime === "application/pdf") return "pdf";
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("text/")) return "text";
  if (mime === "application/json") return "text";

  return "unknown";
}
