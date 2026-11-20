module github.com/openweir/openwrt

go 1.25.0

require (
	aead.dev/minisign v0.3.0
	github.com/klauspost/compress v1.17.9
	golang.org/x/sys v0.12.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/openweir/subconv v0.3.0
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.13.0 // indirect
)

ignore ./build
