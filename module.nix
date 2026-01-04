self:
{ pkgs, snarf, ... }:
{
  options = { };
  config = {
    systemd.services.snarf = {
      wantedBy = [ "sysinit.target" ];
      serviceConfig = {
        ExecStart = "${self.packages.${pkgs.system}.default}/bin/snarfd";
        DynamicUser = true;
        StateDirectory = "snarf";
      };
    };
  };
}
