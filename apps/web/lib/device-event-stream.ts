/** Small bounded SSE parser for signed fetch transport (proofs never enter URLs). */
export function takeSseEvents(buffer: string): { events: string[]; remainder: string } {
  const events: string[] = [];
  let remainder = buffer;
  for (;;) {
    const separator = /\r?\n\r?\n/u.exec(remainder);
    if (!separator || separator.index === undefined) break;
    if (separator.index > 65_536) throw new Error("EVENT_STREAM_FRAME_TOO_LARGE");
    const frame = remainder.slice(0, separator.index);
    remainder = remainder.slice(separator.index + separator[0].length);
    const line = frame.split(/\r?\n/u).find((item) => item.startsWith("event:"));
    if (line) events.push(line.slice(6).trimStart());
  }
  if (remainder.length > 65_536) throw new Error("EVENT_STREAM_FRAME_TOO_LARGE");
  return { events, remainder };
}

export async function consumeDeviceEventStream(response: Response, onEvent: (event: string) => void, signal: AbortSignal): Promise<void> {
  if (!response.body || !response.headers.get("content-type")?.startsWith("text/event-stream")) throw new Error("EVENT_STREAM_INVALID");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (!signal.aborted) {
      const part = await reader.read();
      if (part.done) break;
      buffer += decoder.decode(part.value, { stream: true });
      const parsed = takeSseEvents(buffer);
      buffer = parsed.remainder;
      for (const event of parsed.events) if (!signal.aborted) onEvent(event);
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
