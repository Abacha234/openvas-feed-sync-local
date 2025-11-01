# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702777");
  script_cve_id("CVE-2013-4327", "CVE-2013-4391", "CVE-2013-4394");
  script_tag(name:"creation_date", value:"2013-10-10 22:00:00 +0000 (Thu, 10 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2777)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2777");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2777");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'systemd' package(s) announced via the DSA-2777 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues in systemd have been discovered by Sebastian Krahmer and Florian Weimer: Insecure interaction with DBUS could lead to the bypass of Policykit restrictions and privilege escalation or denial of service through an integer overflow in journald and missing input sanitising in the processing of X keyboard extension (XKB) files.

For the stable distribution (wheezy), these problems have been fixed in version 44-11+deb7u4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your systemd packages.");

  script_tag(name:"affected", value:"'systemd' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);