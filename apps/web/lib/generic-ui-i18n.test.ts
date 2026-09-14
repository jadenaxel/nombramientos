import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { requireAccessibleLabel } from "../components/ui/accessible-label.ts";

const webRoot = path.resolve(import.meta.dirname, "..");

const sources = {
  breadcrumb: readFileSync(path.join(webRoot, "components/ui/breadcrumb.tsx"), "utf8"),
  carousel: readFileSync(path.join(webRoot, "components/ui/carousel.tsx"), "utf8"),
  pagination: readFileSync(path.join(webRoot, "components/ui/pagination.tsx"), "utf8"),
  spinner: readFileSync(path.join(webRoot, "components/ui/spinner.tsx"), "utf8"),
};

test("normaliza etiquetas localizadas y rechaza nombres accesibles vacíos en runtime", () => {
  assert.equal(requireAccessibleLabel("  Página siguiente  ", "TEST"), "Página siguiente");
  assert.throws(
    () => requireAccessibleLabel(" \t ", "TEST"),
    /TEST_ACCESSIBLE_LABEL_REQUIRED/u,
  );
  assert.throws(
    () => requireAccessibleLabel(undefined, "TEST"),
    /TEST_ACCESSIBLE_LABEL_REQUIRED/u,
  );
});

test("paginación exige etiquetas del consumidor y reutiliza las direccionales como texto visible", () => {
  assert.match(sources.pagination, /type PaginationProps[\s\S]*?accessibleLabel: string/u);
  assert.match(sources.pagination, /type PaginationDirectionProps[\s\S]*?label: string/u);
  assert.match(sources.pagination, /aria-label=\{requireAccessibleLabel\(accessibleLabel, "PAGINATION"\)\}/u);
  assert.match(sources.pagination, /aria-label=\{accessibleLabel\}[\s\S]*?>\{accessibleLabel\}<\/span>/u);
  assert.doesNotMatch(sources.pagination, /Go to previous page|Go to next page|>Previous<|>Next<|More pages/u);
});

test("breadcrumb exige nombre localizado y mantiene los adornos fuera del árbol accesible", () => {
  assert.match(sources.breadcrumb, /type BreadcrumbProps[\s\S]*?accessibleLabel: string/u);
  assert.match(sources.breadcrumb, /requireAccessibleLabel\(accessibleLabel, "BREADCRUMB"\)/u);
  assert.match(sources.breadcrumb, /data-slot="breadcrumb-ellipsis"[\s\S]*?aria-hidden="true"/u);
  assert.doesNotMatch(sources.breadcrumb, /aria-label="breadcrumb"|<span className="sr-only">More<\/span>/u);
});

test("carousel concentra todos sus nombres y descripciones de rol en un contrato localizado", () => {
  for (const field of ["region", "roleDescription", "slideRoleDescription", "previous", "next"]) {
    assert.match(sources.carousel, new RegExp(`${field}: string`, "u"));
  }
  assert.match(sources.carousel, /aria-label=\{accessibleLabels\.region\}/u);
  assert.match(sources.carousel, /aria-roledescription=\{accessibleLabels\.roleDescription\}/u);
  assert.match(sources.carousel, /aria-roledescription=\{labels\.slideRoleDescription\}/u);
  assert.match(sources.carousel, /aria-label=\{labels\.previous\}/u);
  assert.match(sources.carousel, /aria-label=\{labels\.next\}/u);
  assert.doesNotMatch(sources.carousel, /aria-roledescription="carousel"|aria-roledescription="slide"|Previous slide|Next slide/u);
});

test("spinner obliga nombre para estados y ofrece una variante decorativa realmente silenciosa", () => {
  assert.match(sources.spinner, /\{ decorative: true; label\?: never \}/u);
  assert.match(sources.spinner, /\{ decorative\?: false; label: string \}/u);
  assert.match(sources.spinner, /role=\{decorative \? undefined : "status"\}/u);
  assert.match(sources.spinner, /aria-hidden=\{decorative \? true : undefined\}/u);
  assert.match(sources.spinner, /requireAccessibleLabel\(label, "SPINNER"\)/u);
  assert.doesNotMatch(sources.spinner, /aria-label="Loading"/u);
});
