class Infraguard < Formula
  desc "IaC compliance pre-check CLI for Alibaba Cloud ROS and Terraform templates"
  homepage "https://github.com/aliyun/infraguard"
  url "https://github.com/aliyun/infraguard/archive/refs/tags/cli/v0.9.0.tar.gz"
  sha256 "34cdd9da54cbd0205e271bce329bc33dc87c2a99c6a6695d2621306521be7765"
  license "Apache-2.0"
  head "https://github.com/aliyun/infraguard.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X github.com/aliyun/infraguard/cmd/infraguard/cmd.Version=#{version}"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/infraguard"
  end

  test do
    output = shell_output("#{bin}/infraguard version")
    assert_match "InfraGuard", output
    assert_match version.to_s, output
  end
end
