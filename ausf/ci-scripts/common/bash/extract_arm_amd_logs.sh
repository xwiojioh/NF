#!/bin/bash

#/*
# * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# * contributor license agreements.  See the NOTICE file distributed with
# * this work for additional information regarding copyright ownership.
# * The OpenAirInterface Software Alliance licenses this file to You under
# * the OAI Public License, Version 1.1  (the "License"); you may not use this file
# * except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *      http://www.openairinterface.org/?page_id=698
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *-------------------------------------------------------------------------------
# * For more information about the OpenAirInterface (OAI) Software Alliance:
# *      contact@openairinterface.org
# */

# Check if the input log file is provided (Example: $ ./extract_arm_amd_logs.sh multiarch_buildx.log)
if [[ $# -ne 1 ]]; then
  echo "Not the correct arguments. Usage: $0 <input_log_file>"
  exit 1
fi

INPUT_LOG="$1"

# Function to extract the AMD and ARM logs
extract_logs() {
  local arch="$1"
  local output_file="$2"
  local current=""

  > "$output_file" # Clear the output file before writing new content

  while IFS= read -r line; do
    [[ "$line" =~ \[.*linux/amd64.*\] ]] && current="amd64" # Detect if line belongs to amd64 and update current
    [[ "$line" =~ \[.*linux/arm64.*\] ]] && current="arm64" # Detect if line belongs to arm64 and update current
    [[ "$current" == "$arch" ]] && echo "$line" >> "$output_file" # If current matches the arch, write to output file
  done < "$INPUT_LOG"
  echo "Extracted logs for $arch architecture to: $output_file"
}

extract_logs "amd64" "archives/ubuntu_image_build_amd64.log"
extract_logs "arm64" "archives/ubuntu_image_build_arm_neoverse_v2.log"
