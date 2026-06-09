import assert from 'node:assert/strict';

import {selectBrowserLocale} from './browserLocaleRedirect';

const supportedLocales = ['en', 'zh', 'es', 'fr', 'de', 'ja', 'pt'];
const defaultLocale = 'en';

function test(name: string, run: () => void) {
  run();
  console.log(`ok - ${name}`);
}

test('uses the first supported browser language', () => {
  assert.equal(
    selectBrowserLocale(['zh-CN', 'fr-FR'], supportedLocales, defaultLocale),
    'zh',
  );
});

test('matches supported regional browser language to base locale', () => {
  assert.equal(
    selectBrowserLocale(['pt-BR', 'en-US'], supportedLocales, defaultLocale),
    'pt',
  );
});

test('normalizes case and underscore separators', () => {
  assert.equal(
    selectBrowserLocale(['ES_mx'], supportedLocales, defaultLocale),
    'es',
  );
});

test('falls back to the default locale when no browser language is supported', () => {
  assert.equal(
    selectBrowserLocale(['it-IT', 'ko-KR'], supportedLocales, defaultLocale),
    'en',
  );
});

test('falls back to the default locale for an empty language list', () => {
  assert.equal(selectBrowserLocale([], supportedLocales, defaultLocale), 'en');
});
