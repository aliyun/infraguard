import Layout from '@theme/Layout'
import BrowserOnly from '@docusaurus/BrowserOnly'
import Playground from '@site/src/components/Playground'

export default function PlaygroundPage() {
  return (
    <Layout title="Playground" description="Scan Alibaba Cloud ROS templates in your browser">
      <main className="container margin-vert--lg">
        <h1>Playground</h1>
        <BrowserOnly fallback={<div>Loading…</div>}>{() => <Playground />}</BrowserOnly>
      </main>
    </Layout>
  )
}
