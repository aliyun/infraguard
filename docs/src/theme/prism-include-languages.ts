/**
 * Custom Prism language inclusion for Docusaurus
 * This file is used to include additional languages that are not natively supported
 */

import {registerRegoLanguage} from './prism-rego';

// Prism type from prismjs package (used by Docusaurus)
type PrismType = {
  languages: {
    [key: string]: any;
  };
};

const prismIncludeLanguages = (prism: PrismType): void => {
  // Register custom Rego language definition
  registerRegoLanguage(prism);
};

export default prismIncludeLanguages;

