function normalizeLocale(locale: string): string | undefined {
  const normalizedLocale = locale.trim().replace(/_/g, '-').toLowerCase();
  return normalizedLocale.length > 0 ? normalizedLocale : undefined;
}

export function selectBrowserLocale(
  browserLanguages: readonly string[] | undefined,
  supportedLocales: readonly string[],
  defaultLocale: string,
): string {
  const supportedLocaleByNormalizedLocale = new Map(
    supportedLocales
      .map((locale) => [normalizeLocale(locale), locale] as const)
      .filter(
        (entry): entry is readonly [string, string] =>
          typeof entry[0] === 'string',
      ),
  );

  for (const browserLanguage of browserLanguages ?? []) {
    const normalizedBrowserLanguage = normalizeLocale(browserLanguage);

    if (!normalizedBrowserLanguage) {
      continue;
    }

    const exactMatch = supportedLocaleByNormalizedLocale.get(
      normalizedBrowserLanguage,
    );

    if (exactMatch) {
      return exactMatch;
    }

    const baseLanguage = normalizedBrowserLanguage.split('-')[0];
    const baseLanguageMatch =
      supportedLocaleByNormalizedLocale.get(baseLanguage);

    if (baseLanguageMatch) {
      return baseLanguageMatch;
    }
  }

  return defaultLocale;
}
