class Faramesh < Formula
  desc "Pre-execution governance engine for AI agents"
  homepage "https://faramesh.dev"
  url "https://github.com/faramesh/faramesh-core/archive/refs/tags/v#{version}.tar.gz"
  license "MPL-2.0"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath",
           "-ldflags", "-s -w -X main.version=#{version}",
           "-o", bin/"faramesh", "./cmd/faramesh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/faramesh --version")
    shell_output("#{bin}/faramesh setup --help")
  end
end
