"use client";

import { message } from "@/lib/product-i18n";

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { Check, Contrast, Gauge, RotateCcw, ScanText } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { Locale } from "@/lib/api";

type TextSize = "standard" | "large" | "extra-large";
type ContrastMode = "standard" | "high";
type MotionMode = "system" | "reduced";
type DensityMode = "comfortable" | "compact";

type AccessibilityPreferences = {
  textSize: TextSize;
  contrast: ContrastMode;
  motion: MotionMode;
  density: DensityMode;
};

type AccessibilityPreferencesValue = {
  preferences: AccessibilityPreferences;
  setPreference: <Key extends keyof AccessibilityPreferences>(key: Key, value: AccessibilityPreferences[Key]) => void;
  reset: () => void;
};

const STORAGE_KEY = "nombramientos.ui-preferences.v1";
const DEFAULT_PREFERENCES: AccessibilityPreferences = {
  textSize: "standard",
  contrast: "standard",
  motion: "system",
  density: "comfortable",
};

const PreferencesContext = createContext<AccessibilityPreferencesValue | undefined>(undefined);

function isPreferences(value: unknown): value is AccessibilityPreferences {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AccessibilityPreferences>;
  return (
    ["standard", "large", "extra-large"].includes(String(candidate.textSize))
    && ["standard", "high"].includes(String(candidate.contrast))
    && ["system", "reduced"].includes(String(candidate.motion))
    && ["comfortable", "compact"].includes(String(candidate.density))
  );
}

function applyPreferences(preferences: AccessibilityPreferences) {
  const root = document.documentElement;
  root.dataset.textSize = preferences.textSize;
  root.dataset.contrast = preferences.contrast;
  root.dataset.motion = preferences.motion;
  root.dataset.density = preferences.density;
}

export function AccessibilityPreferencesProvider({ children }: { children: React.ReactNode }) {
  const [preferences, setPreferences] = useState(DEFAULT_PREFERENCES);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    let next = DEFAULT_PREFERENCES;
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      const parsed: unknown = stored ? JSON.parse(stored) : undefined;
      next = isPreferences(parsed) ? parsed : DEFAULT_PREFERENCES;
      applyPreferences(next);
    } catch {
      applyPreferences(DEFAULT_PREFERENCES);
    }
    const hydrationTimer = window.setTimeout(() => {
      setPreferences(next);
      setHydrated(true);
    }, 0);
    return () => window.clearTimeout(hydrationTimer);
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    applyPreferences(preferences);
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
    } catch {
      // The preference remains effective for this page when storage is unavailable.
    }
  }, [hydrated, preferences]);

  const value = useMemo<AccessibilityPreferencesValue>(() => ({
    preferences,
    setPreference: (key, nextValue) => setPreferences((current) => ({ ...current, [key]: nextValue })),
    reset: () => setPreferences(DEFAULT_PREFERENCES),
  }), [preferences]);

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

function useAccessibilityPreferences() {
  const value = useContext(PreferencesContext);
  if (!value) throw new Error("AccessibilityPreferencesProvider is missing");
  return value;
}

const copy = {
  es: {
    eyebrow: message("es", "screen.accessibilityPreferences.97e89496eae9"),
    title: message("es", "screen.accessibilityPreferences.563acdf1d72a"),
    description: message("es", "screen.accessibilityPreferences.7324ece498b3"),
    size: message("es", "screen.accessibilityPreferences.8c93e4525ef5"),
    contrast: message("es", "screen.accessibilityPreferences.c18cacfa1bba"),
    motion: message("es", "screen.accessibilityPreferences.11bf0e9b55e4"),
    density: message("es", "screen.accessibilityPreferences.52b9c420457a"),
    standard: message("es", "screen.accessibilityPreferences.21e9f7b50a4e"),
    large: message("es", "screen.accessibilityPreferences.f7125bb423f5"),
    extraLarge: message("es", "screen.accessibilityPreferences.9db2919f0ed3"),
    high: message("es", "screen.accessibilityPreferences.4cd71c59de4e"),
    system: message("es", "screen.accessibilityPreferences.a9a8dbe17639"),
    reduced: message("es", "screen.accessibilityPreferences.d328cafbfeb8"),
    comfortable: message("es", "screen.accessibilityPreferences.bea829422181"),
    compact: message("es", "screen.accessibilityPreferences.25f7b2d7a389"),
    reset: message("es", "screen.accessibilityPreferences.ae08793dd1b7"),
    saved: message("es", "screen.accessibilityPreferences.6675daebda1c"),
    theme: message("es", "screen.accessibilityPreferences.96512bd3b47e"),
  },
  en: {
    eyebrow: message("en", "screen.accessibilityPreferences.97e89496eae9"),
    title: message("en", "screen.accessibilityPreferences.563acdf1d72a"),
    description: message("en", "screen.accessibilityPreferences.7324ece498b3"),
    size: message("en", "screen.accessibilityPreferences.8c93e4525ef5"),
    contrast: message("en", "screen.accessibilityPreferences.c18cacfa1bba"),
    motion: message("en", "screen.accessibilityPreferences.11bf0e9b55e4"),
    density: message("en", "screen.accessibilityPreferences.52b9c420457a"),
    standard: message("en", "screen.accessibilityPreferences.21e9f7b50a4e"),
    large: message("en", "screen.accessibilityPreferences.f7125bb423f5"),
    extraLarge: message("en", "screen.accessibilityPreferences.9db2919f0ed3"),
    high: message("en", "screen.accessibilityPreferences.4cd71c59de4e"),
    system: message("en", "screen.accessibilityPreferences.a9a8dbe17639"),
    reduced: message("en", "screen.accessibilityPreferences.d328cafbfeb8"),
    comfortable: message("en", "screen.accessibilityPreferences.bea829422181"),
    compact: message("en", "screen.accessibilityPreferences.25f7b2d7a389"),
    reset: message("en", "screen.accessibilityPreferences.ae08793dd1b7"),
    saved: message("en", "screen.accessibilityPreferences.6675daebda1c"),
    theme: message("en", "screen.accessibilityPreferences.96512bd3b47e"),
  },
  fr: {
    eyebrow: message("fr", "screen.accessibilityPreferences.97e89496eae9"),
    title: message("fr", "screen.accessibilityPreferences.563acdf1d72a"),
    description: message("fr", "screen.accessibilityPreferences.7324ece498b3"),
    size: message("fr", "screen.accessibilityPreferences.8c93e4525ef5"),
    contrast: message("fr", "screen.accessibilityPreferences.c18cacfa1bba"),
    motion: message("fr", "screen.accessibilityPreferences.11bf0e9b55e4"),
    density: message("fr", "screen.accessibilityPreferences.52b9c420457a"),
    standard: message("fr", "screen.accessibilityPreferences.21e9f7b50a4e"),
    large: message("fr", "screen.accessibilityPreferences.f7125bb423f5"),
    extraLarge: message("fr", "screen.accessibilityPreferences.9db2919f0ed3"),
    high: message("fr", "screen.accessibilityPreferences.4cd71c59de4e"),
    system: message("fr", "screen.accessibilityPreferences.a9a8dbe17639"),
    reduced: message("fr", "screen.accessibilityPreferences.d328cafbfeb8"),
    comfortable: message("fr", "screen.accessibilityPreferences.bea829422181"),
    compact: message("fr", "screen.accessibilityPreferences.25f7b2d7a389"),
    reset: message("fr", "screen.accessibilityPreferences.ae08793dd1b7"),
    saved: message("fr", "screen.accessibilityPreferences.6675daebda1c"),
    theme: message("fr", "screen.accessibilityPreferences.96512bd3b47e"),
  },
} as const;

function PreferenceGroup<Value extends string>({
  legend,
  name,
  value,
  options,
  onChange,
}: {
  legend: string;
  name: string;
  value: Value;
  options: ReadonlyArray<{ value: Value; label: string }>;
  onChange: (value: Value) => void;
}) {
  return <fieldset className="preference-group">
    <legend>{legend}</legend>
    <div>
      {options.map((option) => <label className="preference-choice" key={option.value}>
        <input
          checked={value === option.value}
          name={name}
          onChange={() => onChange(option.value)}
          type="radio"
          value={option.value}
        />
        <span>{option.label}</span>
        {value === option.value && <Check aria-hidden="true" />}
      </label>)}
    </div>
  </fieldset>;
}

export function AccessibilityPreferencesPanel({ locale }: { locale: Locale }) {
  const labels = copy[locale];
  const { preferences, reset, setPreference } = useAccessibilityPreferences();
  const [announcement, setAnnouncement] = useState({ sequence: 0, text: "" });

  function applyPreference<Key extends keyof AccessibilityPreferences>(key: Key, value: AccessibilityPreferences[Key], label: string) {
    setPreference(key, value);
    setAnnouncement((current) => ({ sequence: current.sequence + 1, text: `${labels.saved}: ${label}` }));
  }

  function resetPreferences() {
    reset();
    setAnnouncement((current) => ({ sequence: current.sequence + 1, text: labels.saved }));
  }

  return <section className="surface-card accessibility-preferences" aria-labelledby="accessibility-preferences-title">
    <div className="card-heading">
      <div>
        <p className="eyebrow">{labels.eyebrow}</p>
        <h2 id="accessibility-preferences-title">{labels.title}</h2>
      </div>
      <span className="form-icon"><ScanText aria-hidden="true" /></span>
    </div>
    <p>{labels.description}</p>
    <div className="preference-grid">
      <PreferenceGroup<TextSize>
        legend={labels.size}
        name="text-size"
        value={preferences.textSize}
        options={[
          { value: "standard", label: labels.standard },
          { value: "large", label: labels.large },
          { value: "extra-large", label: labels.extraLarge },
        ]}
        onChange={(value) => applyPreference("textSize", value, value === "standard" ? labels.standard : value === "large" ? labels.large : labels.extraLarge)}
      />
      <PreferenceGroup<ContrastMode>
        legend={labels.contrast}
        name="contrast"
        value={preferences.contrast}
        options={[
          { value: "standard", label: labels.standard },
          { value: "high", label: labels.high },
        ]}
        onChange={(value) => applyPreference("contrast", value, value === "high" ? labels.high : labels.standard)}
      />
      <PreferenceGroup<MotionMode>
        legend={labels.motion}
        name="motion"
        value={preferences.motion}
        options={[
          { value: "system", label: labels.system },
          { value: "reduced", label: labels.reduced },
        ]}
        onChange={(value) => applyPreference("motion", value, value === "reduced" ? labels.reduced : labels.system)}
      />
      <PreferenceGroup<DensityMode>
        legend={labels.density}
        name="density"
        value={preferences.density}
        options={[
          { value: "comfortable", label: labels.comfortable },
          { value: "compact", label: labels.compact },
        ]}
        onChange={(value) => applyPreference("density", value, value === "compact" ? labels.compact : labels.comfortable)}
      />
    </div>
    <div className="preference-footer">
      <p><Contrast aria-hidden="true" /> {labels.theme}</p>
      <Button onClick={resetPreferences} type="button" variant="outline"><RotateCcw aria-hidden="true" /> {labels.reset}</Button>
    </div>
    <p className="sr-only" aria-live="polite"><Gauge aria-hidden="true" />{announcement.text && <span key={announcement.sequence}>{announcement.text}</span>}</p>
  </section>;
}
