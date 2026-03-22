# Example Nomad job: agent + faramesh sharing a directory for the Unix socket.
# Policy file: mount from host or bake into image at /policy/policy.yaml.

job "governed-agent" {
  datacenters = ["dc1"]
  type        = "service"

  group "agent" {
    count = 1

    volume "faramesh" {
      type      = "host"
      read_only = false
      source    = "faramesh-workdir"
    }

    task "faramesh" {
      driver = "docker"
      config {
        image = "faramesh:local"
        args = [
          "serve",
          "--policy", "/policy/policy.yaml",
          "--socket", "/alloc/faramesh/faramesh.sock"
        ]
        # Host policy path — configure on Nomad clients or use artifact block instead.
        volumes = ["/opt/faramesh/policy.yaml:/policy/policy.yaml:ro"]
      }
      env {
        FARAMESH_REGION = "global"
      }
      volume_mount {
        volume      = "faramesh"
        destination = "/alloc/faramesh"
        read_only   = false
      }
      resources {
        cpu    = 256
        memory = 256
      }
    }

    task "agent" {
      driver = "docker"
      config {
        image = "your-agent:latest"
      }
      env {
        FARAMESH_SOCKET = "/alloc/faramesh/faramesh.sock"
      }
      volume_mount {
        volume      = "faramesh"
        destination = "/alloc/faramesh"
        read_only   = false
      }
    }
  }
}
