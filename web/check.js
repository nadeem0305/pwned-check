// Same k-anonymity flow as the Go CLI: only the first 5 hex chars of the SHA-1 leave the browser.
export async function sha1Hex(text) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function findCount(body, suffix) {
  for (const line of body.split("\n")) {
    const [hash, count] = line.trim().split(":");
    if (hash?.toUpperCase() === suffix) return Number(count);
  }
  return 0;
}

export async function check(password, fetchFn = fetch) {
  const hash = await sha1Hex(password);
  const res = await fetchFn(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, { headers: { "Add-Padding": "true" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return findCount(await res.text(), hash.slice(5));
}
