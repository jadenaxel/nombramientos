import { getRequestConfig } from "next-intl/server";

import { intlMessages, isLocale } from "@/lib/messages";

export default getRequestConfig(async ({ requestLocale }) => {
  const requested = await requestLocale;
  const locale = requested && isLocale(requested) ? requested : "es";

  return {
    locale,
    messages: intlMessages[locale],
    timeZone: "America/Santo_Domingo",
  };
});
