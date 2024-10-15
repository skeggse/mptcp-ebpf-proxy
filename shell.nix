{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs.buildPackages; [
      bcc
      bpftools
      python3
      #(pkgs.python3.withPackages (ps: [ ps.bcc ]))
      linuxHeaders
    ];

    # TODO: figure out https://github.com/NixOS/nixpkgs/issues/348354
    shellHook = ''
      BCC_PATH="$(tr : '\0' <<< "$PYTHONPATH" | grep --null-data 'bcc.*site-packages' | tr '\0' '\n')"
      export PYTHONPATH="$BCC_PATH/$(cat "$BCC_PATH/easy-install.pth"):$PYTHONPATH"
    '';
}
