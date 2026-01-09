import type { ReactNode } from "react";
import clsx from "clsx";
import Link from "@docusaurus/Link";
import Translate, { translate } from "@docusaurus/Translate";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import Heading from "@theme/Heading";
import CodeBlock from "@theme/CodeBlock";

import styles from "./index.module.css";

function CheckIcon() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        marginRight: "0.8rem",
        color: "var(--ifm-color-primary)",
        flexShrink: 0,
      }}
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx("hero", styles.heroBanner)}>
      <div className="container">
        <div className="row">
          <div className="col col--8">
            <Heading as="h1" className={styles.heroTitle}>
              {siteConfig.title}
            </Heading>
            <p className={styles.heroSubtitle}>
              <Translate
                id="homepage.tagline"
                description="The homepage tagline"
              >
                Policy Defined. Infrastructure Secured.
              </Translate>
            </p>
            <div className={styles.buttons}>
              <Link
                className={clsx(
                  "button button--primary button--lg",
                  styles.button,
                )}
                to="/docs/getting-started/quick-start"
              >
                <Translate
                  id="homepage.getStarted"
                  description="Get started button text"
                >
                  Get Started →
                </Translate>
              </Link>
              <Link
                className={clsx(
                  "button button--outline button--primary button--lg",
                  styles.button,
                )}
                to="https://github.com/aliyun/infraguard"
              >
                GitHub
              </Link>
            </div>
          </div>
          <div className="col col--4">
            <img
              src="img/logo.svg"
              alt="InfraGuard Logo"
              className={styles.heroLogo}
              style={{ maxHeight: "300px", width: "auto" }}
            />
          </div>
        </div>
      </div>
    </header>
  );
}

function CodeExample() {
  const code = `$ infraguard scan template.yaml -p rule:aliyun:ecs-available-disk-encrypted
🔴 High #1 Encryption protects data at rest from unauthorized access.

  template.yaml:8
┌────────┬─────────────────────────────┐
│      6 │       ZoneId: cn-hangzhou-h │
│      7 │       Size: 40              │
│ >    8 │       Encrypted: false      │
└────────┴─────────────────────────────┘

  Rule ID: rule:aliyun:ecs-available-disk-encrypted
  Resource: Disk
  Recommendation: Set the 'Encrypted' property of ECS disks to true.

────────────────────────────────── Scan Results ──────────────────────────────────
  Total: 1 | High: 1 | Medium: 0 | Low: 0`;

  return (
    <section className={styles.codeSection}>
      <div className="container">
        <div className="row">
          <div className="col col--6">
            <Heading as="h2">
              <Translate id="homepage.codeExample.title">
                Catch Issues Early
              </Translate>
            </Heading>
            <p style={{ fontSize: "1.2rem", opacity: 0.8 }}>
              <Translate id="homepage.codeExample.description">
                InfraGuard helps you identify security risks, configuration
                errors, and compliance violations directly in your development
                workflow or CI/CD pipeline.
              </Translate>
            </p>
            <ul
              style={{
                fontSize: "1.1rem",
                opacity: 0.9,
                listStyleType: "none",
                padding: 0,
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
              }}
            >
              <li style={{ display: "flex", alignItems: "center" }}>
                <CheckIcon />
                <Translate id="homepage.codeExample.feature1">
                  Prevent insecure deployments
                </Translate>
              </li>
              <li style={{ display: "flex", alignItems: "center" }}>
                <CheckIcon />
                <Translate id="homepage.codeExample.feature2">
                  Standardize infrastructure across teams
                </Translate>
              </li>
              <li style={{ display: "flex", alignItems: "center" }}>
                <CheckIcon />
                <Translate id="homepage.codeExample.feature3">
                  Automate compliance audits
                </Translate>
              </li>
            </ul>
          </div>
          <div className="col col--6">
            <div className={styles.codeContainer}>
              <CodeBlock language="bash">{code}</CodeBlock>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function InfrastructureCompliance() {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <div className="row">
          <div className="col col--6">
            <Heading as="h2">
              <Translate id="homepage.standardize.title">
                Standardize Your Infrastructure
              </Translate>
            </Heading>

            <p style={{ fontSize: "1.2rem" }}>
              <Translate id="homepage.standardize.description">
                InfraGuard provides a unified way to enforce best practices
                across your organization. Whether you are using standard Aliyun
                compliance packs or your own custom rules, InfraGuard ensures
                consistency and security.
              </Translate>
            </p>

            <div className="padding-vert--md">
              <Link
                className="button button--primary button--lg"
                to="/docs/user-guide/scanning-templates"
              >
                <Translate id="homepage.standardize.learnMore">
                  Learn More
                </Translate>
              </Link>
            </div>
          </div>

          <div className="col col--6">
            <div className="text--center">
              <img
                src="img/standardization.svg"
                alt="Infrastructure Standardization"
                style={{ width: "100%", height: "auto" }}
              />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout
      title={translate({
        id: "homepage.title",

        message: "IaC Compliance Pre-check CLI",

        description: "The homepage title",
      })}
      description={translate({
        id: "homepage.description",

        message:
          "Infrastructure as Code compliance pre-check CLI for Alibaba Cloud ROS templates. Catch security and compliance issues before deployment.",

        description: "The homepage description",
      })}
    >
      <HomepageHeader />

      <main>
        <HomepageFeatures />

        <InfrastructureCompliance />

        <CodeExample />
      </main>
    </Layout>
  );
}
