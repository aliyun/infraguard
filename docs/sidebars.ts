import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

/**
 * Creating a sidebar enables you to:
 * - create an ordered group of docs
 * - render a sidebar for each doc of that group
 * - provide next/previous navigation
 */
const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'doc',
      id: 'intro',
      label: 'Introduction',
    },
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
      ],
    },
    {
      type: 'category',
      label: 'User Guide',
      collapsed: false,
      items: [
        'user-guide/scanning-templates',
        'user-guide/managing-policies',
        'user-guide/output-formats',
        'user-guide/configuration',
      ],
    },
    {
      type: 'category',
      label: 'Policy Reference',
      collapsed: true,
      items: [
        {
          type: 'category',
          label: 'Aliyun',
          collapsed: true,
          items: [
            {
              type: 'category',
              label: 'Rules',
              link: {
                type: 'doc',
                id: 'policies/aliyun/rules',
              },
              collapsed: true,
              items: [
                // Will be auto-generated
              ],
            },
            {
              type: 'category',
              label: 'Packs',
              link: {
                type: 'doc',
                id: 'policies/aliyun/packs',
              },
              collapsed: true,
              items: [
                // Will be auto-generated
              ],
            },
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Development',
      collapsed: true,
      items: [
        'development/writing-rules',
        'development/writing-packs',
        'development/policy-validation',
        'development/helper-functions',
      ],
    },
    {
      type: 'category',
      label: 'CLI Reference',
      collapsed: true,
      items: [
        'cli/scan',
        'cli/policy',
        'cli/config',
      ],
    },
    {
      type: 'doc',
      id: 'faq',
      label: 'FAQ',
    },
  ],
};

export default sidebars;
