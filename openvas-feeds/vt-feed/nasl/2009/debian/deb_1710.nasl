# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63296");
  script_cve_id("CVE-2009-0241");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1710)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1710");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1710");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ganglia-monitor-core' package(s) announced via the DSA-1710 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spike Spiegel discovered a stack-based buffer overflow in gmetad, the meta-daemon for the ganglia cluster monitoring toolkit, which could be triggered via a request with long path names and might enable arbitrary code execution.

For the stable distribution (etch), this problem has been fixed in version 2.5.7-3.1etch1.

For the unstable distribution (sid) this problem has been fixed in version 2.5.7-5.

For the testing distribution (lenny), this problem will be fixed soon.

We recommend that you upgrade your ganglia-monitor-core packages.");

  script_tag(name:"affected", value:"'ganglia-monitor-core' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);