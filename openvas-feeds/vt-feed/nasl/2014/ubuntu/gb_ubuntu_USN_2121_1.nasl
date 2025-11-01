# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841730");
  script_cve_id("CVE-2014-1959");
  script_tag(name:"creation_date", value:"2014-03-04 05:19:19 +0000 (Tue, 04 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2121-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2121-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls26' package(s) announced via the USN-2121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Suman Jana discovered that GnuTLS incorrectly handled version 1
intermediate certificates. This resulted in them being considered to be a
valid CA certificate by default, which was contrary to documented
behaviour.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
