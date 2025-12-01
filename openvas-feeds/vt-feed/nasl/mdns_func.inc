# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Creates a mDNS query message of the given itype type
#
# @param query         The binary query
# @param itype         The query type; for now PTR and HINFO are supported
# @param transactionId The transaction ID to be used
#
# @return The mDNS query message or NULL if not all mandatory info has been passed via the function
#         parameters.
#
function mdns_create_query( query, itype, transactionId ) {

  local_var query, itype, transactionId;
  local_var pkt;

  # nb: isnull() used in the first two to e.g. allow a 0x00
  if( isnull( query ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#query#-#mdns_create_query" );
    return NULL;
  }

  if( isnull( transactionId ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#transactionId#-#mdns_create_query" );
    return NULL;
  }

  if( ! itype ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#itype#-#mdns_create_query" );
    return NULL;
  }

  if( itype != "PTR" && itype != "HINFO" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#mdns_create_query(): Invalid type '" + itype + "' passed to 'itype' parameter. Currently supported: 'PTR' or 'HINFO'." );
    return NULL;
  }

  # DNS Header
  pkt = raw_string( 0x00, transactionId );
  pkt += raw_string( 0x01, 0x00,           # Flags: standard query
                     0x00, 0x01,           # Question count
                     0x00, 0x00,           # Answer count
                     0x00, 0x00,           # Authority RRS
                     0x00, 0x00 );         # Additional RRS
  pkt += query;

  if( itype == "PTR" )
    pkt += raw_string( 0x00, 0x0c, 0x00, 0x01 );

  if( itype == "HINFO" )
    pkt += raw_string( 0x00, 0x0d, 0x00, 0x01, 0x00 );

  return( pkt );
}

# @brief Converts the list of labels to a proper QNAME
#
# @param labels The list of labels
#
# @return The binary QNAME or NULL if the labels function parameter has invalid data passed.
#
function mdns_list_to_qname_query( labels ) {

  local_var labels;
  local_var query, element, length;

  if( ! labels ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#labels#-#mdns_list_to_qname_query" );
    return NULL;
  }

  if( typeof( labels ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#mdns_list_to_qname_query(): No list passed to 'labels' parameter." );
    return NULL;
  }

  query = "";
  foreach element( labels ) {
    length = strlen( element );
    query += raw_string( length ) + element;
  }

  query += raw_string( 0x00 ); # Root
  return query;
}

# @brief Creates a list of known services which can be used to query the available services of a
#        remote mDNS service.
#
# @return The created list

function mdns_create_service_list() {

  local_var list;

  list = make_list( "_services", "_dns-sd", "_udp", "local" );
  return list;
}
