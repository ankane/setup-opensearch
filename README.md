# setup-opensearch

An action for OpenSearch :tada:

- Simpler than containers
- Works on Linux, Mac, and Windows
- Supports different versions

[![Build Status](https://github.com/ankane/setup-opensearch/actions/workflows/build.yml/badge.svg)](https://github.com/ankane/setup-opensearch/actions)

## Getting Started

Add it as a step to your workflow

```yml
      - uses: ankane/setup-opensearch@v1
```

## Versions

Specify a version (defaults to the latest)

```yml
      - uses: ankane/setup-opensearch@v1
        with:
          opensearch-version: 3
```

Supports major versions (`3`, `2`), minor versions (`3.0`, `2.19`, etc), and full versions (`3.0.0`, `2.19.1`, etc), and Windows requires 2.4+

Test against multiple versions

```yml
    strategy:
      matrix:
        opensearch-version: [3, 2]
    steps:
      - uses: ankane/setup-opensearch@v1
        with:
          opensearch-version: ${{ matrix.opensearch-version }}
```

## Options

Install plugins

```yml
      - uses: ankane/setup-opensearch@v1
        with:
          plugins: |
            analysis-kuromoji
            analysis-smartcn
```

Set `opensearch.yml` config

```yml
      - uses: ankane/setup-opensearch@v1
        with:
          config: |
            http.port: 9200
```

## Caching [experimental]

Add a step to your workflow **before** the `setup-opensearch` one

```yml
      - uses: actions/cache@v5
        with:
          path: ~/opensearch
          key: ${{ runner.os }}-opensearch-${{ matrix.opensearch-version }}
```

## Related Actions

- [setup-postgres](https://github.com/ankane/setup-postgres)
- [setup-mysql](https://github.com/ankane/setup-mysql)
- [setup-mariadb](https://github.com/ankane/setup-mariadb)
- [setup-mongodb](https://github.com/ankane/setup-mongodb)
- [setup-elasticsearch](https://github.com/ankane/setup-elasticsearch)
- [setup-sqlserver](https://github.com/ankane/setup-sqlserver)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/setup-opensearch/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/setup-opensearch/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features
