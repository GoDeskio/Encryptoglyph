// Encryptoglyph sidecar client. Drop this file into a GoDesk app.
export class Encryptoglyph {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.sessionId = "";
  }

  async session() {
    const opened = await this.#json("POST", "/v1/sessions", {});
    this.sessionId = opened.session_id;
    return this.sessionId;
  }

  async seal(ctx, plaintext) {
    const bytes = plaintext instanceof Uint8Array ? plaintext : new TextEncoder().encode(plaintext);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return this.#json("POST", "/v1/seal", { ...ctx, plaintext_b64: btoa(binary) });
  }

  async #json(method, path, body) {
    const headers = { "content-type": "application/json" };
    if (this.sessionId) headers["x-eg-session"] = this.sessionId;
    const response = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "encryptoglyph request failed");
    return data;
  }
}
