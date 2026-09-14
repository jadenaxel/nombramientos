import { createTranslator } from "next-intl";

type IcuValues = Readonly<Record<string, string | number>>;
const formatters = new Map<string, (values: IcuValues) => string>();

export function formatIcuMessage(
  locale: string,
  source: string,
  values: IcuValues,
): string {
  const cacheKey = `${locale}\u0000${source}`;
  let formatter = formatters.get(cacheKey);
  if (!formatter) {
    const translator = createTranslator({
      locale,
      messages: { value: source },
      onError: (error) => { throw error; },
    });
    formatter = (input) => translator("value", input);
    formatters.set(cacheKey, formatter);
  }
  return formatter(values);
}
