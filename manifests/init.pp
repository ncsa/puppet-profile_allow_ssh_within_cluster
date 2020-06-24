# @summary Configure public_key based ssh between all specified nodes
#
# Configure sshd for hostbased access between specified nodes
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
#   If 'root' is in users, passwordless root will be allowed.
#   Default: (empty list)
#
# @param ssh_private_key
#   Add this private key to all specified users.
#   If empty, it is assumed user(s) will manage their own keys.
#   Default: null
#
# @param ssh_public_key
#   Add this public key to all specified users and users' authorized_keys file.
#   If null, it is assumed user(s) will manage their own keys.
#   Default: null
#
class profile_allow_ssh_within_cluster (
  Array              $groups,
  Array              $nodelist,
  Optional[ String ] $ssh_private_key,
  Optional[ String ] $ssh_public_key,
  Array              $users,
) {
  $parms_local = {
    'PubkeyAuthentication' => 'yes',
  }

  # check for root
  if 'root' in $users {
    $root = { 'PermitRootLogin' => 'without-password' }
  } else {
    $root = {}
  }

  # create allow_groups
  $groups = { 'AllowGroups' => $groups }

  # join the param hashes
  $params = merge( $parms_local, $root, $groups )

  # update sshd_config & firewall
  ::sshd::allow_from{ 'profile_allow_ssh_within_cluster':
    hostlist                 => $nodelist,
    groups                   => $groups,
    additional_match_params  => $params,
  }

  # create ssh keys and authorized_keys
  $pubkey_parts=split( $ssh_public_key, ' ' )
  $pk_type_raw = $pubkey_parts[0]
  # make sure the filename matches something that ssh will expect
  # since we aren't setting up a .ssh/config file
  $pk_type = $pk_type_raw ? {
    /(ecdsa)/   => $1,
    /(dsa)/     => $1,
    /(rsa)/     => $1,
    /(ed25519)/ => $1,
    default     => $pk_type_raw,
  }
  $pk_key  = $pubkey_parts[1]
  $users.each | $user | {
    $sshdir = $user ? {
      'root'  => '/root/.ssh',
      default => "/home/${user}/.ssh",
    }
    $sshkey_filename = "id_${pk_type}"
    file {
      $sshdir :
        ensure => directory,
        mode   => '0700',
      ;
      "${sshdir}/${sshkey_filename}" :
        content => Sensitive($ssh_private_key),
      ;
      "${sshdir}/${sshkey_filename}.pub" :
        content => $ssh_public_key,
      ;
      default:
        ensure => present,
        owner  => $user,
        mode   => '0600'
      ;
    }
    ssh_authorized_key { $user :
      ensure => 'present',
      user   => $user,
      type   => $pubkey_parts[0],
      key    => $pubkey_parts[1],
    }
  }
}
