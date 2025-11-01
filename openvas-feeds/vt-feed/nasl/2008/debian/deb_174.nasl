# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53429");
  script_cve_id("CVE-2002-1215");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-174)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-174");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-174");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heartbeat' package(s) announced via the DSA-174 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nathan Wallwork discovered a buffer overflow in heartbeat, a subsystem for High-Availability Linux. A remote attacker could send a specially crafted UDP packet that overflows a buffer, leaving heartbeat to execute arbitrary code as root.

This problem has been fixed in version 0.4.9.0l-7.2 for the current stable distribution (woody) and version 0.4.9.2-1 for the unstable distribution (sid). The old stable distribution (potato) doesn't contain a heartbeat package.

We recommend that you upgrade your heartbeat package immediately if you run internet connected servers that are heartbeat-monitored.");

  script_tag(name:"affected", value:"'heartbeat' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);