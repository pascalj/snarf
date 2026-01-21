# Snarf [![Test status](https://github.com/pascalj/snarf/actions/workflows/test.yml/badge.svg)](https://github.com/pascalj/snarf/actions/workflows/test.yml)

Snarf is a small and flexible Nix binary (NAR) cache based on [Snix](https://snix.dev). It consists of a server and a client to upload NAR data and manage the server.

## Status

The project is not ready for production use, but it is functional as a basic cache: please give Snarf a try and report any issues here. A rough roadmap is below:

- [x] `snarfd` server wraps Snix' nar-bridge.
- [x] `snarf` client to perform uploads
- [x] Token-based authentication for uploads and the management interface
- [x] NixOS module
- [x] "Lazy" signing while serving the NAR files
- [ ] Progress metering
- [ ] Simple user and token management
- [ ] Display, manage and delete store data with the client
- [ ] Support of Snix' experimental store configuration
- [ ] Garbage collection and caching policies
- [x] Upstream caches similar to attic
- [ ] Provide statistics

## Usage

The installation via a NixOS module is highly recommended.

### Server installation as a NixOS module

Add Snarf's module to your `nixpkgs.lib.nixosSystem` 

```nix
inputs = {
  # ...
  snarf.url = "github:pascalj/snarf";
};
outputs = {
  # ...
  snarf
}:
{
  #...
  nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
    modules = [
      ./configuration.nix
      snarf.nixosModules.default
    ];
  };
};
```

And then in your configuration, enable the service:

```nix
{
  # ...
  services.snarf = {
    enable = true;
    listenAddress = "0.0.0.0";
    openFirewall = true;
  };
}
```

Deploy the configuration and verify that the server is started with `systemctl status snarf`.

### Uploading from the store

First, you need to initialize the server. The client is authenticated via a token when it uploads store paths to the server. When the server first boots up, it is in an uninitialized state. Initialize the admin token by executing the following:

```sh
$ export SNARF_SERVER_ADDRESS="<your-server-host>:9000"
$ snarf -s create-token
```

Set the environment variable `SNARF_CLIENT_TOKEN` to the token returned by the `create-token` command. 

Second, upload the closure of a path by executing

```sh
$ snarf add-closure /nix/store/...
```

Currently, Snarf uses Nix' sqlite database to compute the closure.

## Design Goals

- Build on top of [Snix](https://snix.dev) and use as much as possible to avoid duplication.
- Similar model to [attic](https://github.com/zhaofengli/attic) (client and server), but avoid multi tenancy and authenticated caches for now. If you are looking for something more tested and feature-complete, take a look at attic.

### Structure

The server binary combines a `snix-store` and the `nar-bridge` functionality. The former part is authenticated via PASETO tokens and can be connected to by providing valid PASETO tokens.
For a Nix user, the server looks like a normal Nix binary cache. For authenticated users, it is an extended Snix store that manages the data.

## Contributing

Contributions are welcome. Please open an issue before submitting PRs to discuss whether a change makes sense before starting to work on it.

## License

This project is licensed under GPL3.
