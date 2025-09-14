# Snarf

This is supposed to become a small, flexible, and fast Nix HTTP (NAR) cache.

## Status

This project is not ready for use.

## Design Goals

- Build on top of [Snix][https://snix.dev) and use as much as possible to avoid duplication.
- Keep gRPC compatibility with Snix (ca)stores as backends.
- Similar model to [attic](https://github.com/zhaofengli/attic) (client and server), but avoid multi tenancy for now.

## License

This project is currently licensed under GPL3.
