# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840041");
  script_cve_id("CVE-2006-5867");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-405-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-405-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fetchmail' package(s) announced via the USN-405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that fetchmail did not correctly require TLS
negotiation in certain situations. This would result in a user's
unencrypted password being sent across the network.

If fetchmail has been configured to use the 'sslproto tls1',
'sslcertck', or 'sslfingerprint' options with a server that does not
correctly support TLS negotiation, this update may cause fetchmail to
(correctly) abort authentication.");

  script_tag(name:"affected", value:"'fetchmail' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
