import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Translate, {translate} from '@docusaurus/Translate';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';

import styles from '@site/src/pages/index.module.css';

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
        marginRight: '0.8rem',
        color: 'var(--ifm-color-primary)',
        flexShrink: 0,
      }}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  const logoUrl = useBaseUrl("/img/logo.svg");
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className="container">
        <div className="row">
          <div className="col col--8">
            <Heading as="h1" className={styles.heroTitle}>
              {siteConfig.title}
            </Heading>
            <p className={styles.heroSubtitle}>
              <Translate id="homepage.tagline" description="The homepage tagline">
                策略定义安全。
              </Translate>
            </p>
            <div className={styles.buttons}>
              <Link
                className={clsx('button button--primary button--lg', styles.button)}
                to="/docs/getting-started/quick-start">
                <Translate id="homepage.getStarted" description="Get started button text">
                  快速开始 →
                </Translate>
              </Link>
              <Link
                className={clsx('button button--outline button--primary button--lg', styles.button)}
                to="https://github.com/aliyun/infraguard">
                GitHub
              </Link>
            </div>
          </div>
          <div className="col col--4">
            <img 
              src={logoUrl} 
              alt="InfraGuard Logo" 
              className={styles.heroLogo} 
              style={{maxHeight: '300px', width: 'auto'}}
            />
          </div>
        </div>
      </div>
    </header>
  );
}

function CodeExample() {
  const code = `$ infraguard scan template.yaml -p rule:aliyun:ecs-available-disk-encrypted
🔴 高 #1 加密可以保护静态数据免受未经授权的物理访问或盗窃。

  template.yaml:8
┌────────┬─────────────────────────────┐
│      6 │       ZoneId: cn-hangzhou-h │
│      7 │       Size: 40              │
│ >    8 │       Encrypted: false      │
└────────┴─────────────────────────────┘

  规则 ID: rule:aliyun:ecs-available-disk-encrypted
  资源: Disk
  修复建议: 将所有ECS磁盘的'Encrypted'属性设置为true。

────────────────────────────────── 检查结果 ──────────────────────────────────
  合计: 1 | 高: 1 | 中: 0 | 低: 0`;

  return (
    <section className={styles.codeSection}>
      <div className="container">
        <div className="row">
          <div className="col col--6">
            <Heading as="h2">
              及早发现问题
            </Heading>
            <p style={{fontSize: '1.2rem', opacity: 0.8}}>
              InfraGuard 帮助您在开发工作流或 CI/CD 流水中直接识别安全风险、配置错误和合规性违规。
            </p>
            <ul style={{
              fontSize: '1.1rem', 
              opacity: 0.9, 
              listStyleType: 'none', 
              padding: 0,
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem'
            }}>
              <li style={{display: 'flex', alignItems: 'center'}}>
                <CheckIcon />
                阻止不安全的部署
              </li>
              <li style={{display: 'flex', alignItems: 'center'}}>
                <CheckIcon />
                在团队间规范基础设施
              </li>
              <li style={{display: 'flex', alignItems: 'center'}}>
                <CheckIcon />
                自动化合规审计
              </li>
            </ul>
          </div>
          <div className="col col--6">
            <div className={styles.codeContainer}>
              <CodeBlock language="bash">
                {code}
              </CodeBlock>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function InfrastructureCompliance() {
  const standardizationUrl = useBaseUrl("/img/standardization.svg");
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <div className="row">
          <div className="col col--6">
            <Heading as="h2">规范您的基础设施</Heading>
            <p style={{fontSize: '1.2rem'}}>
              InfraGuard 提供了一种统一的方法在整个组织中强制执行最佳实践。
              无论您是使用标准的阿里云合规包还是自定义规则，
              InfraGuard 都能确保一致性和安全性。
            </p>
            <div className="padding-vert--md">
              <Link
                className="button button--primary button--lg"
                to="/docs/user-guide/scanning-templates">
                了解更多
              </Link>
            </div>
          </div>
          <div className="col col--6">
            <div className="text--center">
              <img 
                src={standardizationUrl} 
                alt="Infrastructure Standardization" 
                style={{width: '100%', height: 'auto'}}
              />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title={translate({
        id: 'homepage.title',
        message: 'IaC 合规预检 CLI',
        description: 'The homepage title',
      })}
      description={translate({
        id: 'homepage.description',
        message: '专为阿里云 ROS 模板设计的基础设施即代码合规预检 CLI。在部署前捕获安全和合规问题。',
        description: 'The homepage description',
      })}>
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <InfrastructureCompliance />
        <CodeExample />
      </main>
    </Layout>
  );
}