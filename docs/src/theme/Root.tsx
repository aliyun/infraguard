import React, {useEffect, type ReactNode} from 'react';
import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment';
import {useLocation} from '@docusaurus/router';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import {useAlternatePageUtils} from '@docusaurus/theme-common/internal';

import {selectBrowserLocale} from '../browserLocaleRedirect';

const BROWSER_LOCALE_REDIRECT_STORAGE_KEY =
  'infraguard.browserLocaleRedirected';

function getBrowserLanguages(): string[] {
  const languages = [
    ...(navigator.languages ?? []),
    navigator.language,
  ].filter((language): language is string => Boolean(language));

  return [...new Set(languages)];
}

function hasRedirectedForBrowserLocale(): boolean {
  try {
    return (
      sessionStorage.getItem(BROWSER_LOCALE_REDIRECT_STORAGE_KEY) === 'true'
    );
  } catch {
    return false;
  }
}

function markRedirectedForBrowserLocale(): void {
  try {
    sessionStorage.setItem(BROWSER_LOCALE_REDIRECT_STORAGE_KEY, 'true');
  } catch {
    // Ignore browsers or privacy modes where sessionStorage is unavailable.
  }
}

export default function Root({children}: {children: ReactNode}): ReactNode {
  const {
    i18n: {currentLocale, defaultLocale, locales},
  } = useDocusaurusContext();
  const {pathname, search, hash} = useLocation();
  const alternatePageUtils = useAlternatePageUtils();

  useEffect(() => {
    if (!ExecutionEnvironment.canUseDOM) {
      return;
    }

    if (
      currentLocale !== defaultLocale ||
      hasRedirectedForBrowserLocale()
    ) {
      return;
    }

    const selectedLocale = selectBrowserLocale(
      getBrowserLanguages(),
      locales,
      defaultLocale,
    );

    if (selectedLocale === defaultLocale) {
      return;
    }

    const targetPathname = alternatePageUtils.createUrl({
      locale: selectedLocale,
      fullyQualified: false,
    });
    const targetUrl = `${targetPathname}${search}${hash}`;
    const currentUrl = `${pathname}${search}${hash}`;

    markRedirectedForBrowserLocale();

    if (targetUrl !== currentUrl) {
      window.location.replace(targetUrl);
    }
  }, [
    alternatePageUtils,
    currentLocale,
    defaultLocale,
    hash,
    locales,
    pathname,
    search,
  ]);

  return <>{children}</>;
}
