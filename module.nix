self:
{
  pkgs,
  lib,
  snarf,
  config,
  ...
}:
let
  cfg = config.services.snarf;
in
{
  options.services.snarf = with lib; {
    enable = lib.mkEnableOption "snarf Nix binary cache server";

    listenAddress = mkOption {
      default = "127.0.0.1";
      type = types.str;
      description = "The ip address to listen on";
    };
    port = mkOption {
      default = 9000;
      type = types.port;
      description = "The port to listen on";
    };
    openFirewall = mkOption {
      default = false;
      type = types.bool;
      description = "Whether to open the firewall on snarf's listening port";
    };
    blob_service = mkOption {
      default = null;
      type = types.nullOr types.str;
      description = "The blob service address of the underlying Snix store";
    };
    directory_service = mkOption {
      default = null;
      type = types.nullOr types.str;
      description = "The directory service address of the underlying Snix store";
    };
    path_info_service = mkOption {
      default = null;
      type = types.nullOr types.str;
      description = "The path info service address of the underlying Snix store";
    };
    cache_name = mkOption {
      default = null;
      type = types.nullOr types.str;
      description = "The name of the cache, for example for signing";
    };
    state_directory = mkOption {
      default = null;
      type = types.nullOr types.str;
      description = "The directory where snarfd keeps its runtime data";
    };
    extraArgs = mkOption {
      default = [ ];
      type = lib.types.listOf lib.types.str;
      description = "Extra arguments to pass to the deamon";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.snarf = {
      wantedBy = [ "sysinit.target" ];
      after = [ "network.target" ];
      description = "The snarf Nix binary cache server";
      serviceConfig = {
        ExecStart =
          "${self.packages.${pkgs.system}.default}/bin/snarfd -l ${cfg.listenAddress}:${toString cfg.port}"
          + lib.optionalString (cfg.blob_service != null) " --blob-service-addr ${cfg.blob_service}"
          + lib.optionalString (
            cfg.directory_service != null
          ) " --directory-service-addr ${cfg.directory_service}"
          + lib.optionalString (cfg.path_info_service != null) " --path-info-service-addr ${cfg.path_info}"
          + lib.optionalString (cfg.state_directory != null) " --state-directory ${cfg.state_directory}"
          + lib.escapeShellArgs cfg.extraArgs;
        DynamicUser = true;
        StateDirectory = "snarf";
      };
    };
    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [
        cfg.port
      ];
    };
  };
}
