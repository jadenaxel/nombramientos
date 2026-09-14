"use client";

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crop, ImagePlus, LoaderCircle, ShieldCheck, Trash2 } from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  apiRequest,
  idempotencyKey,
  type AuthenticatedSession,
  type Locale,
} from "@/lib/api";
import {
  decryptPhoto,
  encryptPhoto,
  inspectPhotoInput,
  normalizePhoto,
  type NormalizedPhoto,
  type StoredPhotoRecord,
} from "@/lib/photo-client";
import { keyForEnvelope } from "@/lib/historical-envelope";
import { message, localizedApiError } from "@/lib/product-i18n";

type Copy = {
  readonly title: string;
  readonly optional: string;
  readonly empty: string;
  readonly locked: string;
  readonly unavailable: string;
  readonly choose: string;
  readonly accepted: string;
  readonly horizontal: string;
  readonly vertical: string;
  readonly crop: string;
  readonly save: string;
  readonly replace: string;
  readonly archive: string;
  readonly privacyTitle: string;
  readonly privacyBody: string;
  readonly currentAlt: string;
  readonly previewAlt: string;
  readonly normalized: string;
  readonly loading: string;
};

const copy: Readonly<Record<Locale, Copy>> = {
  es: {
    title: message("es", "screen.memberPhotoEditor.8334ebf72909"),
    optional: message("es", "screen.memberPhotoEditor.2ff8d251dc7a"),
    empty: message("es", "screen.memberPhotoEditor.5ce74a7d7c3d"),
    locked: message("es", "screen.memberPhotoEditor.d5a17f92dc05"),
    unavailable: message("es", "screen.memberPhotoEditor.e8eed21166c8"),
    choose: message("es", "screen.memberPhotoEditor.70a927cbf82c"),
    accepted: message("es", "screen.memberPhotoEditor.cf0b49322d27"),
    horizontal: message("es", "screen.memberPhotoEditor.cbd547f7954c"),
    vertical: message("es", "screen.memberPhotoEditor.3059eeb16822"),
    crop: message("es", "screen.memberPhotoEditor.fff0051542d0"),
    save: message("es", "screen.memberPhotoEditor.999d128d442a"),
    replace: message("es", "screen.memberPhotoEditor.5cc1e091536a"),
    archive: message("es", "screen.memberPhotoEditor.bfcf978928b5"),
    privacyTitle: message("es", "screen.memberPhotoEditor.9c5a68d3ef32"),
    privacyBody: message("es", "screen.memberPhotoEditor.063d621ed76e"),
    currentAlt: message("es", "screen.memberPhotoEditor.3460699df851"),
    previewAlt: message("es", "screen.memberPhotoEditor.54411dc49a83"),
    normalized: message("es", "screen.memberPhotoEditor.b75aa344054c"), loading: message("es", "screen.memberPhotoEditor.fcac31b97840"),
  },
  en: {
    title: message("en", "screen.memberPhotoEditor.8334ebf72909"),
    optional: message("en", "screen.memberPhotoEditor.2ff8d251dc7a"),
    empty: message("en", "screen.memberPhotoEditor.5ce74a7d7c3d"),
    locked: message("en", "screen.memberPhotoEditor.d5a17f92dc05"),
    unavailable: message("en", "screen.memberPhotoEditor.e8eed21166c8"),
    choose: message("en", "screen.memberPhotoEditor.70a927cbf82c"),
    accepted: message("en", "screen.memberPhotoEditor.cf0b49322d27"),
    horizontal: message("en", "screen.memberPhotoEditor.cbd547f7954c"),
    vertical: message("en", "screen.memberPhotoEditor.3059eeb16822"),
    crop: message("en", "screen.memberPhotoEditor.fff0051542d0"),
    save: message("en", "screen.memberPhotoEditor.999d128d442a"),
    replace: message("en", "screen.memberPhotoEditor.5cc1e091536a"),
    archive: message("en", "screen.memberPhotoEditor.bfcf978928b5"),
    privacyTitle: message("en", "screen.memberPhotoEditor.9c5a68d3ef32"),
    privacyBody: message("en", "screen.memberPhotoEditor.063d621ed76e"),
    currentAlt: message("en", "screen.memberPhotoEditor.3460699df851"),
    previewAlt: message("en", "screen.memberPhotoEditor.54411dc49a83"),
    normalized: message("en", "screen.memberPhotoEditor.b75aa344054c"), loading: message("en", "screen.memberPhotoEditor.fcac31b97840"),
  },
  fr: {
    title: message("fr", "screen.memberPhotoEditor.8334ebf72909"),
    optional: message("fr", "screen.memberPhotoEditor.2ff8d251dc7a"),
    empty: message("fr", "screen.memberPhotoEditor.5ce74a7d7c3d"),
    locked: message("fr", "screen.memberPhotoEditor.d5a17f92dc05"),
    unavailable: message("fr", "screen.memberPhotoEditor.e8eed21166c8"),
    choose: message("fr", "screen.memberPhotoEditor.70a927cbf82c"),
    accepted: message("fr", "screen.memberPhotoEditor.cf0b49322d27"),
    horizontal: message("fr", "screen.memberPhotoEditor.cbd547f7954c"),
    vertical: message("fr", "screen.memberPhotoEditor.3059eeb16822"),
    crop: message("fr", "screen.memberPhotoEditor.fff0051542d0"),
    save: message("fr", "screen.memberPhotoEditor.999d128d442a"),
    replace: message("fr", "screen.memberPhotoEditor.5cc1e091536a"),
    archive: message("fr", "screen.memberPhotoEditor.bfcf978928b5"),
    privacyTitle: message("fr", "screen.memberPhotoEditor.9c5a68d3ef32"),
    privacyBody: message("fr", "screen.memberPhotoEditor.063d621ed76e"),
    currentAlt: message("fr", "screen.memberPhotoEditor.3460699df851"),
    previewAlt: message("fr", "screen.memberPhotoEditor.54411dc49a83"),
    normalized: message("fr", "screen.memberPhotoEditor.b75aa344054c"), loading: message("fr", "screen.memberPhotoEditor.fcac31b97840"),
  },
};

export function MemberPhotoEditor({
  locale,
  session,
  memberId,
  displayName,
  onChanged,
}: {
  readonly locale: Locale;
  readonly session: AuthenticatedSession;
  readonly memberId: string;
  readonly displayName?: string;
  readonly onChanged?: () => void;
}) {
  const words = copy[locale];
  const vault = useVault();
  const queryClient = useQueryClient();
  const [source, setSource] = useState<File>();
  const [normalized, setNormalized] = useState<NormalizedPhoto>();
  const [focusX, setFocusX] = useState(0.5);
  const [focusY, setFocusY] = useState(0.5);
  const [preparing, setPreparing] = useState(false);
  const [localError, setLocalError] = useState<string>();
  const [currentUrl, setCurrentUrl] = useState<string>();
  const [previewUrl, setPreviewUrl] = useState<string>();
  const putKey = useRef(idempotencyKey());
  const putPayload = useRef<object | undefined>(undefined);
  const archiveKey = useRef(idempotencyKey());
  const mayRead = session.permissions.includes("member.read");
  const mayManage = session.permissions.includes("member.photo.manage");

  const writeContextQuery = useQuery({
    queryKey: ["member-photo-write-context", session.tenant.id, memberId],
    enabled: mayManage,
    queryFn: () => apiRequest<{ expectedVersion: number; nextVersion: number }>(
      `/v1/members/${encodeURIComponent(memberId)}/photo/write-context`,
    ),
  });

  const query = useQuery({
    queryKey: ["member-photo", session.tenant.id, memberId],
    enabled: mayRead,
    queryFn: async () => {
      try {
        return await apiRequest<StoredPhotoRecord>(`/v1/members/${encodeURIComponent(memberId)}/photo`);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
  });

  useEffect(() => {
    let cancelled = false;
    let nextUrl: string | undefined;
    async function openCurrent() {
      setCurrentUrl(undefined);
      if (!query.data || !vault.key || !vault.keyId) return;
      try {
        const blob = await decryptPhoto({
          key: keyForEnvelope(vault, session.tenant.id, query.data.envelope),
          keyId: query.data.envelope.keyId,
          tenantId: session.tenant.id,
          memberId,
          photo: query.data,
        });
        nextUrl = URL.createObjectURL(blob);
        if (!cancelled) {
          setLocalError(undefined);
          setCurrentUrl(nextUrl);
        }
      } catch {
        if (!cancelled) setLocalError(words.unavailable);
      }
    }
    void openCurrent();
    return () => {
      cancelled = true;
      if (nextUrl) URL.revokeObjectURL(nextUrl);
    };
  }, [memberId, query.data, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, words.unavailable]);

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  async function prepare(file = source, x = focusX, y = focusY) {
    if (!file || !vault.key) {
      setLocalError(words.locked);
      return;
    }
    setPreparing(true);
    setLocalError(undefined);
    try {
      await inspectPhotoInput(file);
      const result = await normalizePhoto(file, { x, y });
      setNormalized(result);
      setPreviewUrl(URL.createObjectURL(result.blob));
      putPayload.current = undefined;
      putKey.current = idempotencyKey();
    } catch {
      setNormalized(undefined);
      setPreviewUrl(undefined);
      setLocalError(words.unavailable);
    } finally {
      setPreparing(false);
    }
  }

  const put = useMutation({
    mutationFn: async () => {
      if (!normalized || !vault.key || !vault.keyId || !writeContextQuery.data) throw new Error(words.locked);
      if (!putPayload.current) {
        const photoId = crypto.randomUUID();
        const { expectedVersion, nextVersion } = writeContextQuery.data;
        const sealed = await encryptPhoto({
          key: vault.key,
          keyId: vault.keyId,
          tenantId: session.tenant.id,
          memberId,
          photoId,
          version: nextVersion,
          normalized,
        });
        putPayload.current = {
          photoId,
          expectedVersion,
          version: nextVersion,
          mediaType: normalized.mediaType,
          width: normalized.width,
          height: normalized.height,
          plaintextBytes: normalized.plaintextBytes,
          envelope: sealed.envelope,
          contentHash: sealed.contentHash,
        };
      }
      return apiRequest(`/v1/members/${encodeURIComponent(memberId)}/photo`, {
        method: "POST",
        body: JSON.stringify(putPayload.current),
        idempotent: true,
        idempotencyKey: putKey.current,
      });
    },
    onSuccess: () => {
      setSource(undefined);
      setNormalized(undefined);
      setPreviewUrl(undefined);
      setFocusX(0.5);
      setFocusY(0.5);
      putPayload.current = undefined;
      putKey.current = idempotencyKey();
      void queryClient.invalidateQueries({ queryKey: ["member-photo", session.tenant.id, memberId] });
      void queryClient.invalidateQueries({ queryKey: ["member-photo-write-context", session.tenant.id, memberId] });
      onChanged?.();
    },
  });

  const archive = useMutation({
    mutationFn: async () => {
      if (!query.data) throw new Error(words.empty);
      return apiRequest(`/v1/members/${encodeURIComponent(memberId)}/photo/archive`, {
        method: "POST",
        body: JSON.stringify({ expectedVersion: query.data.version }),
        idempotent: true,
        idempotencyKey: archiveKey.current,
      });
    },
    onSuccess: () => {
      archiveKey.current = idempotencyKey();
      void queryClient.invalidateQueries({ queryKey: ["member-photo", session.tenant.id, memberId] });
      void queryClient.invalidateQueries({ queryKey: ["member-photo-write-context", session.tenant.id, memberId] });
      onChanged?.();
    },
  });

  const visibleError = localError
    ?? (query.error ? localizedApiError(query.error, locale) : undefined)
    ?? (writeContextQuery.error ? localizedApiError(writeContextQuery.error, locale) : undefined)
    ?? (put.error ? localizedApiError(put.error, locale) : undefined)
    ?? (archive.error ? localizedApiError(archive.error, locale) : undefined);

  return (
    <section aria-labelledby={`member-photo-title-${memberId}`} style={{ display: "grid", gap: "1rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: ".75rem" }}>
        <h3 id={`member-photo-title-${memberId}`} style={{ margin: 0 }}>{words.title}</h3>
        <span>{words.optional}</span>
      </div>

      <Alert>
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>{words.privacyTitle}</AlertTitle>
        <AlertDescription>{words.privacyBody}</AlertDescription>
      </Alert>

      {visibleError ? <Alert variant="destructive"><AlertDescription>{visibleError}</AlertDescription></Alert> : null}
      {!vault.key ? <p role="status">{words.locked}</p> : null}

      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "1rem" }}>
        {currentUrl ? (
          // The blob URL exists only in this page's memory and is revoked on change/unmount.
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={currentUrl}
            alt={`${words.currentAlt}${displayName ? `: ${displayName}` : ""}`}
            width={160}
            height={160}
            style={{ width: 160, height: 160, borderRadius: 18, objectFit: "cover" }}
          />
        ) : query.isLoading || (query.data && vault.key && !visibleError) ? (
          <LoaderCircle aria-label={words.loading} className="animate-spin" />
        ) : query.data ? (
          <p>{vault.key ? words.unavailable : words.locked}</p>
        ) : (
          <p>{words.empty}</p>
        )}
        {previewUrl ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={previewUrl}
            alt={words.previewAlt}
            width={160}
            height={160}
            style={{ width: 160, height: 160, borderRadius: 18, objectFit: "cover" }}
          />
        ) : null}
      </div>

      {mayManage ? (
        <div style={{ display: "grid", gap: ".9rem" }}>
          <div style={{ display: "grid", gap: ".35rem" }}>
            <Label htmlFor={`photo-file-${memberId}`}><ImagePlus size={16} aria-hidden="true" /> {words.choose}</Label>
            <Input
              id={`photo-file-${memberId}`}
              type="file"
              accept="image/jpeg,image/png,image/webp"
              disabled={!vault.key || !writeContextQuery.data || preparing || put.isPending}
              onChange={(event) => {
                const selected = event.currentTarget.files?.[0];
                if (!selected) return;
                setSource(selected);
                setFocusX(0.5);
                setFocusY(0.5);
                void prepare(selected, 0.5, 0.5);
              }}
            />
            <small>{words.accepted}</small>
          </div>

          {source ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: ".75rem" }}>
              <Label htmlFor={`photo-focus-x-${memberId}`}>{words.horizontal}
                <input id={`photo-focus-x-${memberId}`} type="range" min="0" max="1" step="0.01" value={focusX}
                  onChange={(event) => setFocusX(Number(event.currentTarget.value))} style={{ width: "100%" }} />
              </Label>
              <Label htmlFor={`photo-focus-y-${memberId}`}>{words.vertical}
                <input id={`photo-focus-y-${memberId}`} type="range" min="0" max="1" step="0.01" value={focusY}
                  onChange={(event) => setFocusY(Number(event.currentTarget.value))} style={{ width: "100%" }} />
              </Label>
            </div>
          ) : null}

          <div style={{ display: "flex", flexWrap: "wrap", gap: ".65rem" }}>
            {source ? <Button type="button" variant="outline" onClick={() => void prepare()} disabled={preparing || put.isPending}>
              {preparing ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <Crop aria-hidden="true" />} {words.crop}
            </Button> : null}
            {normalized ? <Button type="button" onClick={() => put.mutate()} disabled={put.isPending || preparing || !writeContextQuery.data}>
              {put.isPending ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <ShieldCheck aria-hidden="true" />}
              {query.data ? words.replace : words.save}
            </Button> : null}
            {query.data ? <Button type="button" variant="destructive" onClick={() => archive.mutate()} disabled={archive.isPending || put.isPending}>
              {archive.isPending ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <Trash2 aria-hidden="true" />} {words.archive}
            </Button> : null}
          </div>
          {normalized ? <p role="status">{words.normalized}: {normalized.width} × {normalized.height} · {Math.ceil(normalized.plaintextBytes / 1024)} KB</p> : null}
        </div>
      ) : null}
    </section>
  );
}
