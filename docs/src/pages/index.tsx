import type { ReactNode } from "react";
import clsx from "clsx";
import Link from "@docusaurus/Link";
import Translate, { translate } from "@docusaurus/Translate";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import Heading from "@theme/Heading";

import styles from "./index.module.css";

function GitHubIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.7-3.88-1.54-3.88-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.23-1.28-5.23-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 2.9-.39c.98 0 1.97.13 2.9.39 2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .31.21.68.8.56A10.52 10.52 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5z" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      className={styles.checkIcon}
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function Terminal() {
  const t = {
    desc: translate({
      id: "homepage.terminal.desc",
      message: "Encryption protects data at rest from unauthorized access.",
      description: "Terminal: finding description",
    }),
    high: translate({
      id: "homepage.terminal.high",
      message: "High",
      description: "Terminal: high severity label",
    }),
    ruleId: translate({
      id: "homepage.terminal.ruleId",
      message: "Rule ID",
      description: "Terminal: rule id label",
    }),
    resource: translate({
      id: "homepage.terminal.resource",
      message: "Resource",
      description: "Terminal: resource label",
    }),
    recommendation: translate({
      id: "homepage.terminal.recommendation",
      message: "Recommendation",
      description: "Terminal: recommendation label",
    }),
    recValue: translate({
      id: "homepage.terminal.recValue",
      message: "Set the 'Encrypted' property of ECS disks to true.",
      description: "Terminal: recommendation value",
    }),
    scanResults: translate({
      id: "homepage.terminal.scanResults",
      message: "Scan Results",
      description: "Terminal: scan results divider",
    }),
    total: translate({
      id: "homepage.terminal.total",
      message: "Total",
      description: "Terminal: total label",
    }),
    medium: translate({
      id: "homepage.terminal.medium",
      message: "Medium",
      description: "Terminal: medium severity label",
    }),
    low: translate({
      id: "homepage.terminal.low",
      message: "Low",
      description: "Terminal: low severity label",
    }),
  };

  return (
    <div className={styles.terminal}>
      <div className={styles.terminalHeader}>
        <span className={styles.terminalDots}>
          <span /> <span /> <span />
        </span>
        <span className={styles.terminalTitle}>infraguard — scan</span>
      </div>
      <pre className={styles.terminalBody}>
        <code>
          <span className={styles.tLine}>
            <span className={styles.tPrompt}>$</span>{" "}
            <span className={styles.tCmd}>infraguard</span> scan template.yaml{" "}
            <span className={styles.tFlag}>-p</span>{" "}
            rule:aliyun:ecs-available-disk-encrypted
          </span>
          {"\n"}
          <span className={styles.tHigh}>{`🔴 ${t.high} #1`}</span> {t.desc}
          {"\n\n"}
          <span className={styles.tMuted}>{"  template.yaml:8"}</span>
          {"\n"}
          <span className={styles.tBox}>
            {"  ┌────────┬─────────────────────────────┐\n"}
            {"  │      6 │       ZoneId: cn-hangzhou-h │\n"}
            {"  │      7 │       Size: 40              │\n"}
          </span>
          <span className={styles.tBad}>
            {"  │ >    8 │       Encrypted: false      │\n"}
          </span>
          <span className={styles.tBox}>
            {"  └────────┴─────────────────────────────┘"}
          </span>
          {"\n\n"}
          <span className={styles.tMuted}>{`  ${t.ruleId}: `}</span>
          rule:aliyun:ecs-available-disk-encrypted
          {"\n"}
          <span className={styles.tMuted}>{`  ${t.resource}: `}</span>Disk
          {"\n"}
          <span className={styles.tMuted}>{`  ${t.recommendation}: `}</span>
          <span className={styles.tGood}>{t.recValue}</span>
          {"\n\n"}
          <span className={styles.tDivider}>
            {`──────────────────── ${t.scanResults} ────────────────────`}
          </span>
          {"\n"}
          {`  ${t.total}: 1 | `}
          <span className={styles.tHighText}>{`${t.high}: 1`}</span>
          {` | ${t.medium}: 0 | ${t.low}: 0`}
        </code>
      </pre>
    </div>
  );
}

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={styles.hero}>
      <div className={styles.heroGlow} aria-hidden="true" />
      <div className={clsx("container", styles.heroContainer)}>
        <div className={styles.heroContent}>
          <Heading as="h1" className={styles.heroTitle}>
            {siteConfig.title}
          </Heading>

          <p className={styles.heroTagline}>
            <Translate
              id="homepage.tagline"
              description="The homepage tagline"
            >
              Policy Defined. Infrastructure Secured.
            </Translate>
          </p>

          <p className={styles.heroDescription}>
            <Translate id="homepage.heroDescription">
              An Infrastructure as Code compliance pre-check CLI for Alibaba
              Cloud ROS templates. Catch security and compliance issues before
              they ever reach production.
            </Translate>
          </p>

          <div className={styles.buttons}>
            <Link
              className={clsx(styles.btn, styles.btnPrimary)}
              to="/docs/getting-started/quick-start"
            >
              <Translate
                id="homepage.getStarted"
                description="Get started button text"
              >
                Get Started
              </Translate>
              <ArrowIcon />
            </Link>
            <Link
              className={clsx(styles.btn, styles.btnSecondary)}
              to="https://github.com/aliyun/infraguard"
            >
              <GitHubIcon />
              GitHub
            </Link>
          </div>

          <div className={styles.installRow}>
            <code className={styles.installCmd}>
              <span className={styles.installPrompt}>$</span> brew tap
              aliyun/infraguard https://github.com/aliyun/infraguard &amp;&amp;
              brew install infraguard
            </code>
            <span className={styles.installOr}>
              <Translate id="homepage.installOr">or</Translate>
            </span>
            <code className={styles.installCmd}>
              <span className={styles.installPrompt}>$</span> go install
              github.com/aliyun/infraguard/cmd/infraguard@latest
            </code>
          </div>
        </div>

        <div className={styles.heroVisual}>
          <Terminal />
        </div>
      </div>
    </header>
  );
}

const STATS = [
  { value: "300+", labelId: "homepage.stats.rules", label: "Built-in rules" },
  { value: "7", labelId: "homepage.stats.languages", label: "Languages" },
  {
    value: "1",
    labelId: "homepage.stats.binary",
    label: "Zero-dependency binary",
  },
  { value: "Go", labelId: "homepage.stats.speed", label: "Built for speed" },
];

function StatsBar() {
  return (
    <section className={styles.statsSection}>
      <div className={clsx("container", styles.statsGrid)}>
        {STATS.map((stat) => (
          <div key={stat.labelId} className={styles.statItem}>
            <span className={styles.statValue}>{stat.value}</span>
            <span className={styles.statLabel}>
              <Translate id={stat.labelId}>{stat.label}</Translate>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function InfrastructureCompliance() {
  const points = [
    {
      id: "homepage.standardize.point1",
      text: "Prevent insecure deployments before they happen",
    },
    {
      id: "homepage.standardize.point2",
      text: "Standardize infrastructure across every team",
    },
    {
      id: "homepage.standardize.point3",
      text: "Automate compliance audits in your CI/CD pipeline",
    },
  ];

  return (
    <section className={styles.standardize}>
      <div className={clsx("container", styles.standardizeInner)}>
        <div className={styles.standardizeCopy}>
          <span className={styles.eyebrow}>
            <Translate id="homepage.standardize.eyebrow">
              Consistency at scale
            </Translate>
          </span>
          <Heading as="h2" className={styles.sectionTitle}>
            <Translate id="homepage.standardize.title">
              Standardize Your Infrastructure
            </Translate>
          </Heading>
          <p className={styles.sectionLead}>
            <Translate id="homepage.standardize.description">
              InfraGuard gives you a unified way to enforce best practices across
              your organization. Whether you rely on official Aliyun compliance
              packs or your own custom rules, every deployment stays consistent
              and secure.
            </Translate>
          </p>
          <ul className={styles.checkList}>
            {points.map((point) => (
              <li key={point.id}>
                <CheckIcon />
                <Translate id={point.id}>{point.text}</Translate>
              </li>
            ))}
          </ul>
          <Link
            className={clsx(styles.btn, styles.btnPrimary)}
            to="/docs/user-guide/scanning-templates"
          >
            <Translate id="homepage.standardize.learnMore">
              Learn More
            </Translate>
            <ArrowIcon />
          </Link>
        </div>

        <div className={styles.standardizeVisual}>
          <div className={styles.flowCard}>
            <div className={styles.flowStep}>
              <span className={styles.flowNum}>1</span>
              <div>
                <strong>
                  <Translate id="homepage.flow.write">Write</Translate>
                </strong>
                <span>
                  <Translate id="homepage.flow.writeDesc">
                    Author your ROS templates as usual
                  </Translate>
                </span>
              </div>
            </div>
            <div className={styles.flowConnector} aria-hidden="true" />
            <div className={styles.flowStep}>
              <span className={styles.flowNum}>2</span>
              <div>
                <strong>
                  <Translate id="homepage.flow.scan">Scan</Translate>
                </strong>
                <span>
                  <Translate id="homepage.flow.scanDesc">
                    InfraGuard checks them against policy
                  </Translate>
                </span>
              </div>
            </div>
            <div className={styles.flowConnector} aria-hidden="true" />
            <div className={clsx(styles.flowStep, styles.flowStepDone)}>
              <span className={styles.flowNum}>
                <CheckIcon />
              </span>
              <div>
                <strong>
                  <Translate id="homepage.flow.deploy">Deploy</Translate>
                </strong>
                <span>
                  <Translate id="homepage.flow.deployDesc">
                    Ship with confidence, fully compliant
                  </Translate>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function CallToAction() {
  return (
    <section className={styles.cta}>
      <div className={clsx("container", styles.ctaInner)}>
        <Heading as="h2" className={styles.ctaTitle}>
          <Translate id="homepage.cta.title">
            Ready to secure your infrastructure?
          </Translate>
        </Heading>
        <p className={styles.ctaLead}>
          <Translate id="homepage.cta.description">
            Install InfraGuard and run your first compliance scan in under a
            minute.
          </Translate>
        </p>
        <div className={styles.buttons}>
          <Link
            className={clsx(styles.btn, styles.btnPrimary)}
            to="/docs/getting-started/quick-start"
          >
            <Translate id="homepage.getStarted">Get Started</Translate>
            <ArrowIcon />
          </Link>
          <Link
            className={clsx(styles.btn, styles.btnSecondary)}
            to="/docs/policies/aliyun/rules"
          >
            <Translate id="homepage.browsePolicies">Browse Policies</Translate>
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
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
        <StatsBar />
        <HomepageFeatures />
        <InfrastructureCompliance />
        <CallToAction />
      </main>
    </Layout>
  );
}
