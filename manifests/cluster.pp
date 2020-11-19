# @summary Configure public_key based ssh between all specified nodes
#
# Configure sshd for access between specified nodes
# using public key auth for all users specified.
#
# Create user ssh keys and authorized keys.
#
# Setup sshd_config.
#
# @param groups
#   The UNIX / LDAP groups that can login.
#   Default: (empty list)
#
# @param nodelist
#   One or more hostnames / IPs / CIDRs.
#   Cannot be empty.
#
# @param users
#   One or more LOCAL users.
#
#   Hash keys are usernames of local users.
#
#   Leave hash values null to use common defaults.
#
#   Use hash values to specify custom settings. Allowed keys are:
#   - `home`
#
#   Default: (empty hash)
#
#   Example:
#
#   ```
#   users:
#     root:     # defaults to home = /root
#     ausr:     # defaults to home = /home/ausr
#     nova:
#       home: "/var/lib/nova"
#   ```
#
# @param ssh_private_key
#   Add this private key to all specified users.
#   If empty, it is assumed user(s) will manage their own keys.
#   Default: null
#
# @param ssh_public_key
#   Add this public key to all specified users' authorized_keys file.
#   If null, it is assumed user(s) will manage their own keys.
#   Default: null
#
define profile_allow_ssh_within_cluster::cluster (
  Array              $groups           = [],
  Array              $nodelist,
  Optional[ String ] $ssh_private_key,
  Optional[ String ] $ssh_public_key,
  Hash               $users            = {},
) {

  # Convert user hash to define sshdir, using custom home when specified
  $userhash = $users.reduce( {} ) | $memo, $kv | {
    $_username = $kv[0]
    $_userdata = $kv[1]
    $sshdir = $_userdata ? {
      # If _userdata is a Hash, get custom home
      Hash    => "${_userdata['home']}/.ssh",
      # for anything else (includes undef), construct a sane sshdir
      default => $_username ? {
        'root'  => '/root/.ssh',
        default =>   "/home/${_username}/.ssh",
      },
    }
    $memo + { $_username => { 'sshdir' => $sshdir } }
  }

  $parms_local = {
    'PubkeyAuthentication' => 'yes',
  }

  # check for root
  if 'root' in $userhash {
    $root_parms = { 'PermitRootLogin' => 'without-password' }
  } else {
    $root_parms = {}
  }

  # join the param hashes
  $params = merge( $parms_local, $root_parms )

  # update sshd_config & firewall
  $gnames = join( $groups, ',' )
  $unames = join( keys( $users ), ',' )
  $nnames = join( $nodelist, ',' )
  $uniq_name = "${gnames} ${unames} ${nnames}"
  ::sshd::allow_from{ "profile_allow_ssh_within_cluster ${uniq_name}":
    additional_match_params => $params,
    groups                  => $groups,
    hostlist                => $nodelist,
    users                   => keys( $userhash ),
  }

  # create ssh keys and authorized_keys
  if $ssh_public_key =~ String[1] and $ssh_private_key =~ String[1] {
    $pubkey_parts = split( $ssh_public_key, ' ' )
    $pk_type_raw = $pubkey_parts[0]
    # make sure the filename matches something that ssh will expect
    # since we aren't setting up a .ssh/config file
    $pk_type = $pk_type_raw ? {
      /(dsa|rsa|ed25519)/ => $1,
      default             => $pk_type_raw,
    }
    $pk_key  = $pubkey_parts[1]
    $pk_comment  = $pubkey_parts[2]
    $userhash.each | $_username, $_userdata | {
      $sshdir = $_userdata['sshdir']
      $sshkey_filename = "id_${pk_type}"
      file {
        $sshdir :
          ensure => directory,
          mode   => '0700',
        ;
        "${sshdir}/${sshkey_filename}" :
          content => Sensitive($ssh_private_key),
        ;
        default:
          ensure => present,
          owner  => $_username,
          mode   => '0600'
        ;
      }
      # $uniq_name = "profile_allow_ssh_within_cluster ${_username} ${pk_comment}"
      # ssh_authorized_key { $uniq_name :
      ssh_authorized_key { $pk_comment :
        ensure => 'present',
        user   => $_username,
        target => "${sshdir}/authorized_keys",
        type   => $pk_type,
        key    => $pk_key,
      }
    }
  } else {
    notify {'Null public and/or private key, skipping key setup':}
  }
}
