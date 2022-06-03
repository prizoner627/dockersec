# Load dependencies
. ./functions/helper_lib.sh

# Load output formating
. ./functions/output_lib.sh

# Load tests
. ./tests/1_host_configuration.sh
. ./tests/2_docker_daemon_configuration.sh
. ./tests/3_docker_daemon_configuration_files.sh

yell_info

# Warn if not root
if [ "$(id -u)" != "0" ]; then
  warn "$(yell 'Some tests might require root to run')\n"
  sleep 3
fi

host_configuration() {
  check_1
  check_1_1
  check_1_1_1
  check_1_1_2
  check_1_1_3
  check_1_1_4
  check_1_1_5
  check_1_1_6
  check_1_1_7
  check_1_1_8
  check_1_1_9
  check_1_1_10
  check_1_1_11
  check_1_1_12
  check_1_1_13
  check_1_1_14
  check_1_1_15
  check_1_1_16
  check_1_1_17
  check_1_1_18
  check_1_2
  check_1_2_1
  check_1_2_2
  check_1_end
}

docker_daemon_configuration() {
  check_2
  check_2_1
  check_2_2
  check_2_3
  check_2_4
  check_2_5
  check_2_6
  check_2_7
  check_2_8
  check_2_9
  check_2_10
  check_2_11
  check_2_12
  check_2_13
  check_2_14
  check_2_15
  check_2_16
  check_2_17
  check_2_18
  check_2_end
}

docker_daemon_files() {
  check_3
  check_3_1
  check_3_2
  check_3_3
  check_3_4
  check_3_5
  check_3_6
  check_3_7
  check_3_8
  check_3_9
  check_3_10
  check_3_11
  check_3_12
  check_3_13
  check_3_14
  check_3_15
  check_3_16
  check_3_17
  check_3_18
  check_3_19
  check_3_20
  check_3_21
  check_3_22
  check_3_23
  check_3_24
  check_3_end
}

host_configuration
docker_daemon_configuration
docker_daemon_files