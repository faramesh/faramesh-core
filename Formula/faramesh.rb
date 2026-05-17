class Faramesh < Formula
  desc "Pre-execution governance engine for AI agents"
  homepage "https://docs.faramesh.dev"
  license "MPL-2.0"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X main.version=#{version}"
    system "go", "build", *std_go_args(ldflags:), "./cmd/faramesh"
  end

  test do
    assert_match "faramesh", shell_output("#{bin}/faramesh --help")
    shell_output("#{bin}/faramesh init --help")
    shell_output("#{bin}/faramesh run --help")
  end
end
