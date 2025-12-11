# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("ssh_func.inc");
include("host_details.inc");

ERROR_PATTERNS = make_list(
  "error:",
  "Error:",
  "ERROR:",
  "doesn't have a resource type",
  "does not have a resource type",
  "No resources found",
  "not found",
  "command not found",
  "No such file or directory",
  "cannot access",
  "Permission denied"
);

function getKubeApiServerYamlPath(){
    return get_kb_item("Policy/kubernetes/manifests/api_server_yaml");
}

function getKubeControllerManagerYamlPath(){
    return get_kb_item("Policy/kubernetes/manifests/controller_manager_yaml");
}

function getKubeSchedulerYamlPath(){
    return get_kb_item("Policy/kubernetes/manifests/scheduler_yaml");
}

function getEtcdYamlPath(){
    return get_kb_item("Policy/kubernetes/manifests/etcd_yaml");
}

function getKubeadmConfPath(){
    return get_kb_item("Policy/kubernetes/kubelet/kubeadm_conf");
}

function getKubeletYamlPath(){
    return get_kb_item("Policy/kubernetes/kubelet/yaml");
}

function getKubeletConfPath(){
    return get_kb_item("Policy/kubernetes/kubelet/conf");
}

function getKubeSchedulerConfPath(){
    return get_kb_item("Policy/kubernetes/scheduler_conf");
}

function getPkiDirectoryPath(){
    return get_kb_item("Policy/kubernetes/pki");
}

function getEtcdDirectoryPath(){
    return get_kb_item("Policy/kubernetes/etcd");
}

function getAdminCredentialConfPath(){
    return get_kb_item("Policy/kubernetes/admin_cred_conf");
}

function create_result(success, expected, actual, error_message){
  local_var result;

  result = make_array();
  result["success"] = success;
  result["expected"] = expected;
  result["actual"] = actual;
  result["error_message"] = error_message;

  return result;
}

function join_list(list, sep){
  local_var list, sep;
  local_var result, i, max_idx;

  if(!list || max_index(list) < 0){
    return "";
  }

  result = "";
  max_idx = max_index(list);
  for(i = 0; i <= max_idx; i++){
    if(i > 0){
      result = result + sep;
    }
    result = result + list[i];
  }

  return result;
}

function runQuery(cmd){
  local_var sock, result;
  local_var error_found, error_msg;

  sock = ssh_login_or_reuse_connection();

  if (!sock){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "SSH connection failed");
  }

  result = ssh_cmd(socket: sock,
                   cmd: cmd,
                   return_errors: TRUE,
                   return_linux_errors_only: TRUE);

  ssh_close_connection(sock);

  if (eregmatch(string: result, pattern: "Permission denied", icase: TRUE)){
    return create_result(success: FALSE,
                         expected: "",
                         actual: result,
                         error_message: "SSH permission denied");
  }

  error_found = FALSE;
  error_msg = "";

  foreach pattern (ERROR_PATTERNS){
    if(eregmatch(string: result, pattern: pattern, icase: TRUE)){
      error_found = TRUE;
      local_var lines, line;
      lines = split(result, sep:'\n', keep:FALSE);
      foreach line (lines){
        if(line && strlen(line) > 0){
          if(eregmatch(string: line, pattern: pattern, icase: TRUE)){
            if(strlen(error_msg) > 0){
              error_msg = error_msg + "; ";
            }
            error_msg = error_msg + line;
            break;
          }
        }
      }
      if(strlen(error_msg) == 0){
        error_msg = "Command execution error detected";
      }
      break;
    }
  }

  if(error_found){
    return create_result(success: FALSE,
                         expected: "",
                         actual: result,
                         error_message: error_msg);
  }

  if(!result){
    result = "";
  }

  return create_result(success: TRUE,
                       expected: "",
                       actual: result,
                       error_message: "");
}

function check_file_permissions(file_path, uread, uwrite, uexec, gread, gwrite, gexec, oread, owrite, oexec){
  local_var file_path, uread, uwrite, uexec, gread, gwrite, gexec, oread, owrite, oexec;
  local_var cmd, query_result, ret, parts, current_permission_str, current_permission;
  local_var owner_perm, group_perm, other_perm;
  local_var owner_read, owner_write, owner_exec;
  local_var group_read, group_write, group_exec;
  local_var other_read, other_write, other_exec;
  local_var violations, compliant;

  if(!file_path){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "Missing required parameters");
  }

  cmd = "stat -c '%a %n' " + file_path + " 2>/dev/null";

  query_result = runQuery(cmd);

  if(!query_result["success"]){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "File does not exist or cannot be read: " + file_path + " (" + query_result["error_message"] + ")");
  }

  ret = query_result["actual"];

  parts = split(ret, sep:' ', keep:FALSE);
  if(max_index(parts) < 1){
    return create_result(success: FALSE,
                         expected: "",
                         actual: ret,
                         error_message: "Could not parse stat output");
  }

  current_permission_str = parts[0];
  current_permission = int(current_permission_str);

  if(!current_permission && current_permission != 0){
    return create_result(success: FALSE,
                         expected: "",
                         actual: current_permission_str,
                         error_message: "Invalid permission format");
  }

  owner_perm = current_permission / 100;
  group_perm = (current_permission / 10) % 10;
  other_perm = current_permission % 10;

  owner_read = (owner_perm & 4) != 0;
  owner_write = (owner_perm & 2) != 0;
  owner_exec = (owner_perm & 1) != 0;
  group_read = (group_perm & 4) != 0;
  group_write = (group_perm & 2) != 0;
  group_exec = (group_perm & 1) != 0;
  other_read = (other_perm & 4) != 0;
  other_write = (other_perm & 2) != 0;
  other_exec = (other_perm & 1) != 0;

  violations = make_list();
  compliant = TRUE;

  if(uread == "unset" && owner_read){
    violations = make_list(violations, "Owner read permission should not be set (uread=unset)");
    compliant = FALSE;
  }

  if(uwrite == "unset" && owner_write){
    violations = make_list(violations, "Owner write permission should not be set (uwrite=unset)");
    compliant = FALSE;
  }

  if(uexec == "unset" && owner_exec){
    violations = make_list(violations, "Owner execute permission should not be set (uexec=unset)");
    compliant = FALSE;
  }

  if(gread == "unset" && group_read){
    violations = make_list(violations, "Group read permission should not be set (gread=unset)");
    compliant = FALSE;
  }

  if(gwrite == "unset" && group_write){
    violations = make_list(violations, "Group write permission should not be set (gwrite=unset)");
    compliant = FALSE;
  }

  if(gexec == "unset" && group_exec){
    violations = make_list(violations, "Group execute permission should not be set (gexec=unset)");
    compliant = FALSE;
  }

  if(oread == "unset" && other_read){
    violations = make_list(violations, "Other read permission should not be set (oread=unset)");
    compliant = FALSE;
  }

  if(owrite == "unset" && other_write){
    violations = make_list(violations, "Other write permission should not be set (owrite=unset)");
    compliant = FALSE;
  }

  if(oexec == "unset" && other_exec){
    violations = make_list(violations, "Other execute permission should not be set (oexec=unset)");
    compliant = FALSE;
  }

  local_var error_msg;
  if(compliant){
    error_msg = "";
  }
  else{
    error_msg = join_list(violations, "; ");
  }

  local_var actual_msg;
  actual_msg = "Permissions: " + ret;

  return create_result(success: compliant,
                        expected: "",
                        actual: actual_msg,
                        error_message: error_msg);
}

function check_file_ownership(file_path, uid, gid){
  local_var file_path, uid, gid;
  local_var cmd, query_result, ret, parts, uid_gid, current_uid_str, current_gid_str;
  local_var current_uid, current_gid, required_uid, required_gid;
  local_var violations, compliant;

  if(!file_path){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "Missing required parameters");
  }

  required_uid = uid;
  required_gid = gid;

  if(required_uid == "" && required_gid == ""){
    return create_result(success: TRUE,
                         expected: "",
                         actual: "",
                         error_message: "Ownership not checked (uid and gid empty)");
  }

  cmd = "stat -c '%u:%g %n' " + file_path + " 2>/dev/null";

  query_result = runQuery(cmd);

  if(!query_result["success"]){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "File does not exist or cannot be read: " + file_path + " (" + query_result["error_message"] + ")");
  }

  ret = query_result["actual"];

  parts = split(ret, sep:' ', keep:FALSE);

  if(max_index(parts) < 1){
    return create_result(success: FALSE,
                         expected: "",
                         actual: ret,
                         error_message: "Could not parse stat output");
  }

  uid_gid = split(parts[0], sep:':', keep:FALSE);

  if(max_index(uid_gid) < 1){
    return create_result(success: FALSE,
                         expected: "",
                         actual: parts[0],
                         error_message: "Could not parse uid:gid");
  }

  current_uid_str = uid_gid[0];
  current_gid_str = uid_gid[1];
  current_uid = int(current_uid_str);
  current_gid = int(current_gid_str);

  violations = make_list();
  compliant = TRUE;

  if(required_uid != "" && int(required_uid) != current_uid){
    violations = make_list(violations, "File should be owned by UID " + required_uid + " but is owned by UID " + current_uid_str);
    compliant = FALSE;
  }

  if(required_gid != "" && int(required_gid) != current_gid){
    violations = make_list(violations, "File should be owned by GID " + required_gid + " but is owned by GID " + current_gid_str);
    compliant = FALSE;
  }

  local_var error_msg;
  if(compliant){
    error_msg = "";
  }
  else{
    error_msg = join_list(violations, "; ");
  }

  local_var actual_msg;
  actual_msg = "Ownership: " + ret;

  return create_result(success: compliant,
                        expected: required_uid + ":" + required_gid,
                        actual: actual_msg,
                        error_message: error_msg);
}

function check_file_content_pattern(file_path, pattern, operation, existence, check){
  local_var file_path, pattern, operation, existence, check;
  local_var cmd, query_result, ret, pattern_found;
  local_var violations, compliant, check_type;

  if(!file_path || !pattern || !operation){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "Missing required parameters");
  }

  check_type = check;

  cmd = "grep -E '" + pattern + "' " + file_path + " 2>/dev/null";

  query_result = runQuery(cmd);

  if(!query_result["success"]){
    if(existence == "at_least_one_exists" || existence == "any_exist"){
      return create_result(success: FALSE,
                           expected: pattern,
                           actual: "",
                           error_message: "File does not exist or cannot be read: " + file_path + " (" + query_result["error_message"] + ")");
    }
    else{
      pattern_found = FALSE;
    }
  }
  else{
    ret = query_result["actual"];
    if(ret && strlen(ret) > 0){
      pattern_found = TRUE;
    }
    else{
      pattern_found = FALSE;
    }
  }

  violations = make_list();
  compliant = TRUE;

  if(operation == "pattern match"){
    if(!pattern_found){
      compliant = FALSE;
      violations = make_list(violations, "Pattern not found in file: " + pattern);
    }
  }
  else if(operation == "pattern not match"){
    if(pattern_found){
      compliant = FALSE;
      violations = make_list(violations, "Pattern found in file (should not exist): " + pattern);
    }
  }
  else{
    compliant = FALSE;
    violations = make_list(violations, "Unknown operation: " + operation);
  }

  local_var actual_output, actual_msg, error_msg;
  if(query_result["success"]){
    actual_output = query_result["actual"];
  }
  else{
    actual_output = "";
  }

  if(pattern_found){
    actual_msg = "Pattern found: " + actual_output;
  }
  else{
    actual_msg = "Pattern not found: " + actual_output;
  }

  if(compliant){
    error_msg = "";
  }
  else{
    error_msg = join_list(violations, "; ");
  }

  return create_result(success: compliant,
                        expected: pattern,
                        actual: actual_msg,
                        error_message: error_msg);
}

function check_process_command_line(process_name, command_line_pattern, check_existence, check){
  local_var process_name, command_line_pattern, check_existence, check;
  local_var cmd, query_result, ret, lines, processes_found, processes_matching;
  local_var violations, compliant;
  local_var check_type;
  local_var i, line, matches;

  if(!process_name || !command_line_pattern){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "Missing required parameters");
  }

  check_type = check;

  cmd = "ps -ef | grep " + process_name + " | grep -v grep";

  query_result = runQuery(cmd);

  if(!query_result["success"]){
    if(check_existence == "at_least_one_exists" || check_existence == "any_exist"){
      return create_result(success: FALSE,
                           expected: command_line_pattern,
                           actual: "",
                           error_message: "Process not found: " + process_name + " (" + query_result["error_message"] + ")");
    }
    else{
      return create_result(success: TRUE,
                           expected: command_line_pattern,
                           actual: "",
                           error_message: "Process not found (existence check not required)");
    }
  }

  ret = query_result["actual"];

  if(!ret || strlen(ret) == 0){
    if(check_existence == "at_least_one_exists" || check_existence == "any_exist"){
      return create_result(success: FALSE,
                           expected: command_line_pattern,
                           actual: "",
                           error_message: "Process not found: " + process_name);
    }
    else{
      return create_result(success: TRUE,
                           expected: command_line_pattern,
                           actual: "",
                           error_message: "Process not found (existence check not required)");
    }
  }

  lines = split(ret, sep:'\n', keep:FALSE);
  processes_found = 0;
  processes_matching = 0;
  violations = make_list();

  foreach line (lines){
    if(line && strlen(line) > 0){
      processes_found++;

      matches = eregmatch(string:line, pattern:command_line_pattern);

      if(matches){
        processes_matching++;
      }
    }
  }

  compliant = TRUE;

  if(check_existence == "at_least_one_exists" || check_existence == "any_exist"){
    if(processes_found == 0){
      compliant = FALSE;
      violations = make_list(violations, "Process not found: " + process_name);
    }
  }

  if(check_type == "all"){
    if(processes_found > 0 && processes_matching != processes_found){
      compliant = FALSE;
      violations = make_list(violations, "Not all processes match pattern. Found: " + processes_found + ", Matching: " + processes_matching);
    }
  }
  else if(check_type == "none satisfy"){
    if(processes_matching > 0){
      compliant = FALSE;
      violations = make_list(violations, "Found " + processes_matching + " process(es) matching pattern (should be 0)");
    }
  }

  local_var actual_msg, error_msg;
  if(processes_found > 0){
    actual_msg = "Found " + processes_found + " process(es), " + processes_matching + " matching: " + ret;
  }
  else{
    actual_msg = "No processes found: " + ret;
  }

  if(compliant){
    error_msg = "";
  }
  else{
    error_msg = join_list(violations, "; ");
  }

  return create_result(success: compliant,
                        expected: command_line_pattern,
                        actual: actual_msg,
                        error_message: error_msg);
}

function check_command_output(command, output_pattern, operation){
  local_var command, output_pattern, operation;
  local_var query_result, ret, output, pattern_found, matches;
  local_var violations, compliant;

  if(!command || !output_pattern || !operation){
    return create_result(success: FALSE,
                         expected: "",
                         actual: "",
                         error_message: "Missing required parameters");
  }

  query_result = runQuery(cmd : command);

  if(!query_result["success"]){
    local_var error_output;
    if(query_result["actual"]){
      error_output = "Command execution failed: " + command + " (" + query_result["error_message"] + "). Output: " + query_result["actual"];
    }
    else{
      error_output = "Command execution failed: " + command + " (" + query_result["error_message"] + ")";
    }
    return create_result(success: FALSE,
                         expected: output_pattern,
                         actual: error_output,
                         error_message: query_result["error_message"]);
  }

  output = query_result["actual"];

  if(!output){
    output = "";
  }

  local_var lines, line, trimmed_line;
  lines = split(output, sep:'\n', keep:FALSE);
  pattern_found = FALSE;

  foreach line (lines){
    if(line && strlen(line) > 0){
      trimmed_line = ereg_replace(string:line, pattern:"^[ \t\r]+", replace:"");
      trimmed_line = ereg_replace(string:trimmed_line, pattern:"[ \t\r]+$", replace:"");
      matches = eregmatch(string:trimmed_line, pattern:output_pattern);
      if(matches){
        pattern_found = TRUE;
        break;
      }
    }
  }

  if(!pattern_found){
    matches = eregmatch(string:output, pattern:output_pattern);
    if(matches){
      pattern_found = TRUE;
    }
  }

  violations = make_list();
  compliant = TRUE;

  if(operation == "pattern match"){
    if(!pattern_found){
      compliant = FALSE;
      violations = make_list(violations, "Pattern not found in output: " + output_pattern);
    }
  }
  else if(operation == "pattern not match"){
    if(pattern_found){
      compliant = FALSE;
      violations = make_list(violations, "Pattern found in output (should not exist): " + output_pattern);
    }
  }
  else{
    compliant = FALSE;
    violations = make_list(violations, "Unknown operation: " + operation);
  }

  local_var actual_msg, error_msg;
  local_var display_output;

  if(output && strlen(output) > 0){
    display_output = output;
  }
  else{
    display_output = "No output";
  }

  if(pattern_found){
    actual_msg = "Pattern found: " + display_output;
  }
  else{
    actual_msg = "Pattern not found: " + display_output;
  }

  if(compliant){
    error_msg = "";
  }
  else{
    error_msg = join_list(violations, "; ");
  }

  return create_result(success: compliant,
                        expected: output_pattern,
                        actual: actual_msg,
                        error_message: error_msg);
}

function get_file_permissions_action(file_path){
  return "Run: stat -c '%a %n' " + file_path;
}

function get_file_permissions_expected(uread, uwrite, uexec, gread, gwrite, gexec, oread, owrite, oexec){
  local_var expected_desc, restrictions;

  restrictions = make_list();

  if(uread == "unset"){
    restrictions = make_list(restrictions, "owner read should NOT be set");
  }
  if(uwrite == "unset"){
    restrictions = make_list(restrictions, "owner write should NOT be set");
  }
  if(uexec == "unset"){
    restrictions = make_list(restrictions, "owner execute should NOT be set");
  }
  if(gread == "unset"){
    restrictions = make_list(restrictions, "group read should NOT be set");
  }
  if(gwrite == "unset"){
    restrictions = make_list(restrictions, "group write should NOT be set");
  }
  if(gexec == "unset"){
    restrictions = make_list(restrictions, "group execute should NOT be set");
  }
  if(oread == "unset"){
    restrictions = make_list(restrictions, "other read should NOT be set");
  }
  if(owrite == "unset"){
    restrictions = make_list(restrictions, "other write should NOT be set");
  }
  if(oexec == "unset"){
    restrictions = make_list(restrictions, "other execute should NOT be set");
  }
  if(max_index(restrictions) > 0){
    expected_desc = "Should have restrictive permissions: " + join_list(restrictions, ", ");
  }
  else{
    expected_desc = "No specific permission restrictions (all permissions are NA or allowed)";
  }

  return expected_desc;
}

function get_file_ownership_action(file_path){
  return "Run: stat -c '%u:%g %n' " + file_path;
}

function get_file_ownership_expected(uid, gid){
  local_var expected_desc, uid_name, gid_name;

  if(uid == "" && gid == ""){
    return "Ownership check not required (uid and gid empty)";
  }
  expected_desc = "Should return ";

  if(uid != "" && gid != ""){
    if(uid == "0"){
      uid_name = "root";
    }
    else{
      uid_name = "UID " + uid;
    }
    if(gid == "0"){
      gid_name = "root";
    }
    else{
      gid_name = "GID " + gid;
    }
    expected_desc += uid + ":" + gid + " (" + uid_name + ":" + gid_name + ")";
  }
  else if(uid != ""){
    if(uid == "0"){
      uid_name = "root";
    }
    else{
      uid_name = "UID " + uid;
    }
    expected_desc += "UID " + uid + " (" + uid_name + ")";
  }
  else if(gid != ""){
    if(gid == "0"){
      gid_name = "root";
    }
    else{
      gid_name = "GID " + gid;
    }
    expected_desc += "GID " + gid + " (" + gid_name + ")";
  }

  return expected_desc;
}

function get_file_content_pattern_action(file_path, pattern){
  return "Run: grep -E '" + pattern + "' " + file_path;
}

function get_file_content_pattern_expected(operation, pattern){
  local_var expected_desc;

  if(operation == "pattern match"){
    expected_desc = "Pattern should be found in file: " + pattern;
  }
  else if(operation == "pattern not match"){
    expected_desc = "Pattern should NOT be found in file: " + pattern;
  }
  else{
    expected_desc = "Unknown operation: " + operation;
  }

  return expected_desc;
}

function get_process_command_line_action(process_name){
  return "Run: ps -ef | grep " + process_name + " | grep -v grep";
}

function get_process_command_line_expected(command_line_pattern, check_existence, check){
  local_var expected_desc;

  expected_desc = "Process command line should ";

  if(check == "all"){
    expected_desc += "contain pattern in all instances: " + command_line_pattern;
  }
  else if(check == "none satisfy"){
    expected_desc += "NOT contain pattern in any instance: " + command_line_pattern;
  }
  else{
    expected_desc += "contain pattern: " + command_line_pattern;
  }

  if(check_existence == "at_least_one_exists" || check_existence == "any_exist"){
    expected_desc += " (process must exist)";
  }

  return expected_desc;
}

function get_command_output_action(command){
  return "Run: " + command;
}

function get_command_output_expected(output_pattern, operation){
  local_var expected_desc;

  if(operation == "pattern match"){
    expected_desc = "Output should contain pattern: " + output_pattern;
  }
  else if(operation == "pattern not match"){
    expected_desc = "Output should NOT contain pattern: " + output_pattern;
  }
  else{
    expected_desc = "Unknown operation: " + operation;
  }

  return expected_desc;
}
