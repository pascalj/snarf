# Rough design sketch

- Have a single binary that serves the grpc services and the nar-bridge together.
- Authentication via [PASETO](https://github.com/rrrodzilla/rusty_paseto)
- First, keep everything very simple (single-tenant, single cache, no fancy signing)
- Add a minimal client that authenticates and then accesses the raw store via grpc
- After everything is set up, add a grpc interface for configuration
- Try to use the experimental composition Snix feature
