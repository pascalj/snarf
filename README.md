# Snarf

Snarf is supposed to become a small, flexible, and fast Nix HTTP (NAR) cache based on [Snix](https://snix.dev).

## Status

The project is not ready for use, but it works.

To run, start the server and copy the [PASETO](https://paseto.io/) token for the client from its output:

```
RUST_LOG=info server
```

And initialize it by generating a new token:

```
RUST_LOG=info client --token "dummy" create-token
```

Pass the token to the client and ingest a closure from your local store:

```
export SNARF_CLIENT_TOKEN=<token>
nix path-info --json --closure-size --recursive <store-path> | \
  jq -s '{closure: add}' | \
  client add - 
```

The server should now have the closure available for caching:

```
curl http://localhost:9000/<store-path-hash>.narinfo
```

## Design Goals

- Build on top of [Snix](https://snix.dev) and use as much as possible to avoid duplication.
- Keep gRPC compatibility with Snix (ca)stores as backends.
- Similar model to [attic](https://github.com/zhaofengli/attic) (client and server), but avoid multi tenancy and authenticated caches for now.

### Structure

Currently, the server binary combines a `snix-store` and the `nar-bridge` functionality. The former part is authenticated via PASETO tokens and can be connected to by providing valid PASETO tokens.
For Nix user, the server looks like a normal Nix binary cache. For authenticated users, it is an extended `snix-store` that manages the underlying store via gRPC.

## License

This project is licensed under GPL3.
