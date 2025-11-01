# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840186");
  script_cve_id("CVE-2007-1384", "CVE-2007-1385");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-436-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-436-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ktorrent' package(s) announced via the USN-436-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bryan Burns of Juniper Networks discovered that KTorrent did not
correctly validate the destination file paths nor the HAVE statements
sent by torrent peers. A malicious remote peer could send specially
crafted messages to overwrite files or execute arbitrary code with user
privileges.");

  script_tag(name:"affected", value:"'ktorrent' package(s) on Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
