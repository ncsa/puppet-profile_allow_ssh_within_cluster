# @summary Configure public_key based ssh between a list of nodes
#
# @param clusters
#   An array of hashes that conform to the parameters required by the
#   profile_allow_ssh_within_cluster::cluster defined type.
#
#   Default: (empty list)
#
#   Example:
#
#   ```
#   profile_allow_ssh_within_cluster::clusters:
#     - users:
#         root:
#       nodelist: "172.30.2.0/24"
#       ssh_private_key: "...a private key as a string..."
#       ssh_public_key: "...a public ssh key as a string..."
#     - users:
#         nova:
#           home: "/var/lib/nova"
#       nodelist: "172.30.2.0/24"
#       ssh_private_key: "...a different private key as a string..."
#       ssh_public_key: "...a different public ssh key as a string..."
#   ```
#
class profile_allow_ssh_within_cluster (
  Array $clusters,
) {

  $clusters.each | $index, $data | {
    profile_allow_ssh_within_cluster::cluster {
      "profile_allow_ssh_within_cluster init ${index}" :
        * =>  $data
    }
  }

}
