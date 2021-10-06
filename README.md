# setup-opensearch

An action for OpenSearch :tada:

- Simpler than containers
- Works on Linux
- Supports different versions

[![Build Status](https://github.com/ankane/setup-opensearch/workflows/build/badge.svg?branch=v1)](https://github.com/ankane/setup-opensearch/actions)

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
        opensearch-version: 1
```

Supports major versions (`1`), minor versions (`1.1`, etc), and full versions (`1.1.0`, etc)

Test against multiple versions

```yml
    strategy:
      matrix:
        opensearch-version: [1.1, 1.0]
    steps:
    - uses: ankane/setup-opensearch@v1
      with:
        opensearch-version: ${{ matrix.opensearch-version }}
```

## Plugins

Install plugins

```yml
    - uses: ankane/setup-opensearch@v1
      with:
        plugins: |
          analysis-kuromoji
          analysis-smartcn
```

## Caching [experimental]

Add a step to your workflow **before** the `setup-opensearch` one

```yml
    - uses: actions/cache@v2
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
