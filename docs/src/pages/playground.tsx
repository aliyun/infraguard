import Layout from '@theme/Layout'
import BrowserOnly from '@docusaurus/BrowserOnly'
import Playground from '@site/src/components/Playground'

export default function PlaygroundPage() {
  return (
    <Layout title="Playground" description="Scan Alibaba Cloud ROS templates against compliance rules in your browser">
      <main className="container margin-vert--lg">
        <BrowserOnly fallback={<div>Loading…</div>}>{() => <Playground />}</BrowserOnly>
      </main>
    </Layout>
  )
}
