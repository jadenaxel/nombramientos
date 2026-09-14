import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import fontkit from "@pdf-lib/fontkit";
import { PDFDocument } from "pdf-lib";

test("the local report font embeds Spanish and French Unicode without substitution", async () => {
  const reportSource = await readFile(new URL("./report-export.ts", import.meta.url), "utf8");
  assert.match(reportSource, /report-sans-regular\.ttf/u);
  assert.match(reportSource, /report-sans-bold\.ttf/u);
  assert.match(reportSource, /embedFont\(regularBytes, \{ subset: true/u);
  assert.doesNotMatch(reportSource, /embedFont\(fontBytes, \{ subset: false/u);
  const document = await PDFDocument.create();
  document.registerFontkit(fontkit);
  const [regularBytes, boldBytes, license] = await Promise.all([
    readFile(new URL("../public/fonts/report-sans-regular.ttf", import.meta.url)),
    readFile(new URL("../public/fonts/report-sans-bold.ttf", import.meta.url)),
    readFile(new URL("../public/fonts/bitstream-vera-license.txt", import.meta.url), "utf8"),
  ]);
  assert.deepEqual([...regularBytes.subarray(0, 4)], [0, 1, 0, 0], "report font must be a raw TrueType sfnt, not WOFF2");
  assert.deepEqual([...boldBytes.subarray(0, 4)], [0, 1, 0, 0], "bold report font must be a raw TrueType sfnt");
  assert.match(license, /Bitstream Vera Fonts Copyright/u);
  const font = await document.embedFont(regularBytes, { subset: true, customName: "Bitstream Vera Sans" });
  const bold = await document.embedFont(boldBytes, { subset: true, customName: "Bitstream Vera Sans Bold" });
  const page = document.addPage();

  page.drawText("Elección · Español · Église · français · cœur", { font, size: 12 });
  page.drawText("Vacantes aplicables — página 1 / 1", { font: bold, size: 12, y: 700, x: 50 });

  const bytes = await document.save();
  assert.ok(bytes.byteLength > 8_000, "both valid TrueType subsets must be embedded in the PDF");
});
