import type { ReactNode } from "react";
import clsx from "clsx";
import Translate from "@docusaurus/Translate";
import Heading from "@theme/Heading";
import styles from "./styles.module.css";

import useBaseUrl from "@docusaurus/useBaseUrl";

type FeatureItem = {
  titleId: string;
  titleDefault: string;
  iconPath: string;
  descriptionId: string;
  descriptionDefault: string;
};

const FeatureList: FeatureItem[] = [
  {
    titleId: "homepage.features.preDeployment.title",
    titleDefault: "Pre-deployment Validation",
    iconPath: "/img/features/validation.svg",
    descriptionId: "homepage.features.preDeployment.description",
    descriptionDefault:
      "Catch compliance and security issues before they reach production. Scan your ROS templates locally during development.",
  },
  {
    titleId: "homepage.features.builtInRules.title",
    titleDefault: "Hundreds of Built-in Rules",
    iconPath: "/img/features/rules.svg",
    descriptionId: "homepage.features.builtInRules.description",
    descriptionDefault:
      "Comprehensive coverage for Aliyun services including ECS, RDS, OSS, ACK, and more with dozens of compliance packs.",
  },
  {
    titleId: "homepage.features.outputFormats.title",
    titleDefault: "Multiple Formats",
    iconPath: "/img/features/formats.svg",
    descriptionId: "homepage.features.outputFormats.description",
    descriptionDefault:
      "Get results in table, JSON, or interactive HTML reports. Easily integrate with CI/CD pipelines.",
  },
  {
    titleId: "homepage.features.extensible.title",
    titleDefault: "Extensible & Open",
    iconPath: "/img/features/extensible.svg",
    descriptionId: "homepage.features.extensible.description",
    descriptionDefault:
      "Write custom policies using Rego (Open Policy Agent). Built on proven technologies and fully open source.",
  },
  {
    titleId: "homepage.features.i18n.title",
    titleDefault: "Internationalization",
    iconPath: "/img/features/i18n.svg",
    descriptionId: "homepage.features.i18n.description",
    descriptionDefault:
      "Full support for 7 languages: English, Chinese, Spanish, French, German, Japanese, and Portuguese. All rules, packs, and documentation available in multiple languages.",
  },
  {
    titleId: "homepage.features.fast.title",
    titleDefault: "Fast & Lightweight",
    iconPath: "/img/features/fast.svg",
    descriptionId: "homepage.features.fast.description",
    descriptionDefault:
      "Built in Go for speed and efficiency. Single binary with no dependencies. Scan large templates in seconds.",
  },
];

function Feature({
  titleId,
  titleDefault,
  iconPath,
  descriptionId,
  descriptionDefault,
}: FeatureItem) {
  return (
    <div className={clsx("col col--4 padding--md")}>
      <div className={styles.featureCard}>
        <div className="text--center">
          <div className={styles.featureIcon}>
            <img src={useBaseUrl(iconPath)} width="48" height="48" alt="" />
          </div>
        </div>
        <div className="text--center">
          <Heading as="h3" className={styles.featureTitle}>
            <Translate id={titleId}>{titleDefault}</Translate>
          </Heading>
          <p className={styles.featureDescription}>
            <Translate id={descriptionId}>{descriptionDefault}</Translate>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
