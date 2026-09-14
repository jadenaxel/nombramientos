import type { CatalogSource } from "./types.js";

export const catalogSources = [
  {
    id: "SDA_CM_2025_EN",
    title: "Seventh-day Adventist Church Manual",
    authority: "General Conference of Seventh-day Adventists",
    kind: "primary_manual",
    edition: "21st edition, revised 2025",
    sourceLanguage: "en",
    url: "https://gc.adventist.org/wp-content/uploads/2025/10/Seventh-day_Adventist_Church_Manual-2025-10-13.pdf",
    consultedOn: "2026-09-13",
    reviewStatus: "verified_primary_source",
    redistribution: "link_only",
    notes:
      "Portada, tabla de contenido, capítulo 9 y la lista de muestra de cargos de las páginas impresas 191–192 fueron cotejados en la fuente oficial. La paginación conserva página impresa y página PDF; un revisor eclesiástico debe confirmar la aplicación territorial.",
  },
  {
    id: "SDA_CHURCH_MANUAL_PORTAL",
    title: "Church Manual portal",
    authority: "General Conference of Seventh-day Adventists",
    kind: "primary_manual",
    edition: null,
    sourceLanguage: "en",
    url: "https://gc.adventist.org/church-manual/",
    consultedOn: "2026-09-13",
    reviewStatus: "verified_primary_source",
    redistribution: "link_only",
    notes:
      "Portal oficial de acceso. Debe revalidarse al actualizar el paquete normativo porque el documento enlazado puede cambiar.",
  },
  {
    id: "SDA_ELDERS_HANDBOOK_2016_EN",
    title: "Seventh-day Adventist Elder's Handbook",
    authority: "Ministerial Association, General Conference of Seventh-day Adventists",
    kind: "official_supporting_manual",
    edition: "Revised 2016",
    sourceLanguage: "en",
    url: "https://cdn.ministerialassociation.org/docs/ebooks/Seventh-day%20Adventist%20Elder%27s%20Handbook%20%28rev.2016%29.pdf",
    consultedOn: "2026-09-10",
    reviewStatus: "verified_official_supporting_source",
    redistribution: "link_only",
    notes:
      "Material oficial de apoyo. No reemplaza ni prevalece sobre el Manual de Iglesia vigente y no se declara como la última edición mundial.",
  },
] as const satisfies readonly CatalogSource[];

export const pendingAuthorityInputs = [
  {
    id: "OZAMA_ASSOCIATION_MISSION",
    label: "Asociación o misión aplicable a Iglesia Adventista Ozama",
    status: "pending_regional_validation",
  },
  {
    id: "OZAMA_UNION",
    label: "Unión aplicable a Iglesia Adventista Ozama",
    status: "pending_regional_validation",
  },
  {
    id: "OZAMA_DIVISION",
    label: "División y suplementos vigentes aplicables a Iglesia Adventista Ozama",
    status: "pending_regional_validation",
  },
  {
    id: "OZAMA_LOCAL_POLICY",
    label: "Prácticas locales aprobadas y terminología institucional",
    status: "pending_local_approval",
  },
] as const;
