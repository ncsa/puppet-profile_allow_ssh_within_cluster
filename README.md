# profile_allow_ssh_within_cluster

NCSA Common Puppet Profiles - allow passwordless ssh between nodes in a cluster

## Dependencies
- [ncsa/sshd](https://github.com/ncsa/puppet-sshd)

## Reference
### define profile_allow_ssh_within_cluster::cluster (
-  Array              $groups,
-  Array              $nodelist,
-  Optional[ String ] $ssh_private_key,
-  Optional[ String ] $ssh_public_key,
-  Hash               $users,
### class profile_allow_ssh_within_cluster (
-  Array $clusters,

See also: [REFERENCE.md](REFERENCE.md)
