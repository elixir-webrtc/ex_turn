defmodule ExTURN.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_turn,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # code coverage
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.json": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ex_stun, github: "elixir-webrtc/ex_stun", branch: "uri"},

      # dev/test
      {:excoveralls, "~> 0.17.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end
