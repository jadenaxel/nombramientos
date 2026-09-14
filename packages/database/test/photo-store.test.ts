import { describe, expect, it } from "vitest";
import { PHOTO_MEDIA_TYPE, PhotoStoreError } from "../src/photo-store.js";

describe("photo storage contract", () => {
  it("declares one normalized media type and neutral public store errors", () => {
    expect(PHOTO_MEDIA_TYPE).toBe("image/jpeg");
    expect(new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found")).toMatchObject({
      statusCode: 404,
      code: "PHOTO_NOT_FOUND",
      message: "Photograph was not found",
    });
  });
});
