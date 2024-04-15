# ExTURN

[![Hex.pm](https://img.shields.io/hexpm/v/ex_turn.svg)](https://hex.pm/packages/ex_turn)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://hexdocs.pm/ex_turn)
[![CI](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/ex_turn/ci.yml?logo=github&label=CI)](https://github.com/elixir-webrtc/ex_turn/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/elixir-webrtc/ex_turn/graph/badge.svg?token=VPsTinh1BK)](https://codecov.io/gh/elixir-webrtc/ex_turn)

In-memory implementation of the TURN client.

Implements:
* [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766)

## Installation

```elixir
def deps do
  [
    {:ex_turn, "~> 0.1.0"}
  ]
end
```