// docker-bake.hcl
group "default" {
  targets = ["latte-dev"]
}

target "latte-dev" {
  context    = "."
  dockerfile = "docker/Dockerfile"
  tags       = ["tee-flow-inspector/dev:latest"]
  platforms  = ["linux/amd64", "linux/arm64/v8"]
}
