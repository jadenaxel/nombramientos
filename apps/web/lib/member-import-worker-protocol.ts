import type {
  ImportColumnMapping,
  ImportExistingMember,
  ImportLocale,
  ImportPreviewRow,
} from "./member-import";

export type ImportSheetDescriptor = {
  readonly name: string;
  readonly rowCount: number;
  readonly headers: readonly string[];
};

export type InspectImportFileRequest = {
  readonly requestId: string;
  readonly type: "inspect";
  readonly bytes: ArrayBuffer;
  readonly extension: "csv" | "xlsx";
  readonly locale: ImportLocale;
};

export type BuildImportPreviewRequest = {
  readonly requestId: string;
  readonly type: "preview";
  readonly datasetId: string;
  readonly sheetName: string;
  readonly mapping: ImportColumnMapping;
  readonly existingMembers: readonly ImportExistingMember[];
  readonly tenantId: string;
  readonly locale: ImportLocale;
};

export type MemberImportWorkerRequest = InspectImportFileRequest | BuildImportPreviewRequest;

export type InspectImportFileResult = {
  readonly datasetId: string;
  readonly sourceFingerprint: `sha256:${string}`;
  readonly sheets: readonly ImportSheetDescriptor[];
};

export type BuildImportPreviewResult = {
  readonly rows: readonly ImportPreviewRow[];
};

export type MemberImportWorkerResponse =
  | {
    readonly requestId: string;
    readonly ok: true;
    readonly type: "inspect";
    readonly result: InspectImportFileResult;
  }
  | {
    readonly requestId: string;
    readonly ok: true;
    readonly type: "preview";
    readonly result: BuildImportPreviewResult;
  }
  | {
    readonly requestId: string;
    readonly ok: false;
    readonly message: string;
  };
