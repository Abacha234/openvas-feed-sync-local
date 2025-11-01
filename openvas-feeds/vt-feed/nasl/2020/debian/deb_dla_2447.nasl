# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892447");
  script_tag(name:"creation_date", value:"2020-11-12 04:00:08 +0000 (Thu, 12 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-2447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2447");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2447-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pacemaker");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pacemaker' package(s) announced via the DLA-2447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update of pacemaker released as DLA-2447-1 caused a regression when the communication between the Corosync cluster engine and pacemaker takes place. A permission problem prevents IPC requests between cluster nodes. The patch for CVE-2020-25654 has been reverted until a better solution can be found.

For Debian 9 stretch, this problem has been fixed in version 1.1.16-1+deb9u2.

We recommend that you upgrade your pacemaker packages.

For the detailed security status of pacemaker please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);