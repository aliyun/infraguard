class Infraguard < Formula
  desc "IaC compliance pre-check CLI for Alibaba Cloud ROS templates"
  homepage "https://github.com/aliyun/infraguard"
  url "https://github.com/aliyun/infraguard/archive/refs/tags/cli/v0.8.0.tar.gz"
  sha256 "4082d5fc92a4eb6e3d0d35a5a13ad58ec75ee25c6318c55718fa1ce52310b0ec"
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
